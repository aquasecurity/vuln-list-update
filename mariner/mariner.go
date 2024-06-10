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
	// CBL Mariner was rebranded to Azure Linux for version 3.0. The same repo is used for both CBL Mariner and Azure Linux vulnerability data.
	repoURL  = "https://github.com/microsoft/AzureLinuxVulnerabilityData/archive/refs/heads/main.tar.gz//AzureLinuxVulnerabilityData-main"
	cblDir   = "mariner" // CBL-Mariner Vulnerability Data
	azureDir = "azure"   // Azure Linux Vulnerability Data
	retry    = 3

	testsDir       = "tests"
	objectsDir     = "objects"
	statesDir      = "states"
	definitionsDir = "definitions"

	azurePrefix   = "azurelinux-"
	marinerPrefix = "cbl-mariner-"
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
		dir:   utils.VulnListDir(),
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

	log.Printf("Remove CBL-Mariner Vulnerability Data directory %s", c.dir)
	if err := os.RemoveAll(filepath.Join(c.dir, cblDir)); err != nil {
		return xerrors.Errorf("failed to remove CBL-Mariner Vulnerability Data directory: %w", err)
	}
	log.Printf("Remove Azure Linux Vulnerability Data directory %s", c.dir)
	if err := os.RemoveAll(filepath.Join(c.dir, azureDir)); err != nil {
		return xerrors.Errorf("failed to remove Azure Linux Vulnerability Data directory: %w", err)
	}

	log.Print("Fetching Azure Linux and CBL-Mariner Vulnerability Data")
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

		if !(strings.HasPrefix(entry.Name(), marinerPrefix) || strings.HasPrefix(entry.Name(), azurePrefix)) {
			continue
		}
		if filepath.Ext(entry.Name()) != ".xml" {
			continue
		}

		osVersion := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(entry.Name(), azurePrefix), marinerPrefix), "-oval.xml"), "-preview")
		if err := c.update(osVersion, filepath.Join(tmpDir, entry.Name()), strings.HasPrefix(entry.Name(), azurePrefix)); err != nil {
			return xerrors.Errorf("failed to update oval data: %w", err)
		}
	}
	return nil
}

func (c Config) update(version, path string, isAzureLinux bool) error {
	f, err := os.Open(path)
	if err != nil {
		return xerrors.Errorf("failed to open file: %w", err)
	}

	var oval OvalDefinitions
	if err := xml.NewDecoder(f).Decode(&oval); err != nil {
		return xerrors.Errorf("failed to decode xml: %w", err)
	}
	dirPath := filepath.Join(c.dir, azureDir, version)
	if !isAzureLinux {
		dirPath = filepath.Join(c.dir, cblDir, version)
	}

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
	// Use advisory_id for file name to avoid overwriting files when there are 2 definitions for same CVE
	// cf. https://github.com/aquasecurity/trivy-db/issues/379
	fileName := fmt.Sprintf("%s.json", AdvisoryID(def))

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

// AdvisoryID returns advisoryID for Definition.
// If `advisory_id` field does not exist, create this field yourself using the Azure Linux format.
//
// Azure Linux uses `<number_after_last_colon_from_id>-<last_number_from_version>` format for `advisory_id`.
// cf. https://github.com/aquasecurity/vuln-list-update/pull/271#issuecomment-2111678641
// e.g.
//   - `id="oval:com.microsoft.cbl-mariner:def:27423" version="2000000001"` => `27423-1`
//   - `id="oval:com.microsoft.cbl-mariner:def:11073" version="2000000000"` => `11073`
//   - `id="oval:com.microsoft.cbl-mariner:def:6343" version="1"` => `6343-1`
//   - `id="oval:com.microsoft.cbl-mariner:def:6356" version="0"` => `6356`
func AdvisoryID(def Definition) string {
	id := def.Metadata.AdvisoryID
	if id == "" {
		ss := strings.Split(def.ID, ":")
		id = ss[len(ss)-1]
		// for `0` versions `-0` suffix is omitted.
		if def.Version != "" && def.Version[len(def.Version)-1:] != "0" {
			id = fmt.Sprintf("%s-%s", id, def.Version[len(def.Version)-1:])
		}
	}
	return id
}
