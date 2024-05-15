package mariner

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/cheggaaa/pb"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	repoURL = "https://github.com/microsoft/CBL-MarinerVulnerabilityData/archive/refs/heads/main.tar.gz//CBL-MarinerVulnerabilityData-main"
	cblDir  = "mariner" // CBL-Mariner Vulnerability Data
	retry   = 3

	testsDir       = "tests"
	objectsDir     = "objects"
	statesDir      = "states"
	definitionsDir = "definitions"
)

var (
	ErrInvalidCVEFormat = errors.New("invalid CVE-ID format")
	ErrNonCVEID         = errors.New("discovered non-CVE-ID")
)

type Config struct {
	*options
}

type option func(*options)

type options struct {
	url   string
	dir   string
	retry int
}

func WithURL(url string) option {
	return func(opts *options) { opts.url = url }
}

func WithDir(dir string) option {
	return func(opts *options) { opts.dir = dir }
}

func WithRetry(retry int) option {
	return func(opts *options) { opts.retry = retry }
}

func NewConfig(opts ...option) Config {
	o := &options{
		url:   repoURL,
		dir:   filepath.Join(utils.VulnListDir(), cblDir),
		retry: retry,
	}

	for _, opt := range opts {
		opt(o)
	}

	return Config{
		options: o,
	}
}

func (c Config) Update() error {
	ctx := context.Background()

	log.Printf("Remove CBL-Mariner Vulnerability Data directory %sn", c.dir)
	if err := os.RemoveAll(c.dir); err != nil {
		return xerrors.Errorf("failed to remove CBL-Mariner Vulnerability Data directory: %w", err)
	}

	log.Print("Fetching CBL-Mariner Vulnerability Data")
	tmpDir, err := utils.DownloadToTempDir(ctx, c.url)
	if err != nil {
		return xerrors.Errorf("failed to retrieve CBL-Mariner Vulnerability Data: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return xerrors.Errorf("failed to read directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if !strings.HasPrefix(entry.Name(), "cbl-mariner-") {
			continue
		}
		if filepath.Ext(entry.Name()) != ".xml" {
			continue
		}

		osVersoin := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(entry.Name(), "cbl-mariner-"), "-oval.xml"), "-preview")
		if err := c.update(osVersoin, filepath.Join(tmpDir, entry.Name())); err != nil {
			return xerrors.Errorf("failed to update oval data: %w", err)
		}
	}
	return nil
}

func (c Config) update(version, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return xerrors.Errorf("failed to open file: %w", err)
	}

	var oval OvalDefinitions
	if err := xml.NewDecoder(f).Decode(&oval); err != nil {
		return xerrors.Errorf("failed to decode xml: %w", err)
	}
	dirPath := filepath.Join(c.dir, version)

	// write tests/tests.json file
	if err := utils.Write(filepath.Join(dirPath, testsDir, "tests.json"), oval.Tests); err != nil {
		return xerrors.Errorf("failed to write tests: %w", err)
	}

	// write objects/objects.json file
	if err := utils.Write(filepath.Join(dirPath, objectsDir, "objects.json"), oval.Objects); err != nil {
		return xerrors.Errorf("failed to write objects: %w", err)
	}

	// write states/states.json file
	if err := utils.Write(filepath.Join(dirPath, statesDir, "states.json"), oval.States); err != nil {
		return xerrors.Errorf("failed to write states: %w", err)
	}

	// write definitions
	bar := pb.StartNew(len(oval.Definitions.Definition))
	for _, def := range oval.Definitions.Definition {
		if err := c.saveAdvisoryPerYear(filepath.Join(dirPath, definitionsDir), def); err != nil {
			return xerrors.Errorf("failed to save advisory per year: %w", err)
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}
func (c Config) saveAdvisoryPerYear(dirName string, def Definition) error {
	// Mariner uses `<ID>_<last_number_from_version>` format for `advisory_id`.
	// But `advisory_id` is not required field.
	// Therefore, if `advisory_id` is not exist, we create this field independently.
	// cf. https://github.com/aquasecurity/vuln-list-update/pull/271#issuecomment-2111678641
	advisoryID := def.Metadata.AdvisoryID
	if advisoryID == "" {
		advisoryID = def.ID
		// for `0` versions `_0` suffix is omitted.
		if def.Version != "" && def.Version[len(def.Version)-1:] != "0" {
			advisoryID = fmt.Sprintf("%s_%s", advisoryID, def.Version[len(def.Version)-1:])
		}
	}
	// Use advisory_id for file name to avoid overwriting files when there are 2 definitions for same CVE
	// cf. https://github.com/aquasecurity/trivy-db/issues/379
	fileName := fmt.Sprintf("%s.json", advisoryID)

	vulnID := def.Metadata.Reference.RefID
	if !strings.HasPrefix(vulnID, "CVE") {
		log.Printf("discovered non-CVE-ID: %s", vulnID)
		return ErrNonCVEID
	}

	s := strings.Split(vulnID, "-")
	if len(s) != 3 {
		log.Printf("invalid CVE-ID format: %s", vulnID)
		return ErrInvalidCVEFormat
	}

	yearDir := filepath.Join(dirName, s[1])
	if err := utils.Write(filepath.Join(yearDir, fileName), def); err != nil {
		return xerrors.Errorf("unable to write a JSON file: %w", err)
	}
	return nil
}
