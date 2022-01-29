package cblmariner

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/cheggaaa/pb"
	"golang.org/x/xerrors"
)

const (
	repoURL = "https://github.com/microsoft/CBL-MarinerVulnerabilityData/archive/refs/heads/main.tar.gz//CBL-MarinerVulnerabilityData-main"
	cblDir  = "cbl-mariner" // CBL Mariner Vulnerability Data
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

func WithURLs(url string) option {
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

	log.Printf("Remove CBL Mariner Vulnerability Data directory %s\n", c.dir)
	if err := os.RemoveAll(c.dir); err != nil {
		return xerrors.Errorf("failed to remove CBL-Mariner Vulnerability Data directory: %w", err)
	}

	log.Print("Fetching CBL Mariner Vulnerability Data")
	tmpDir, err := utils.DownloadToTempDir(ctx, c.url)
	if err != nil {
		return xerrors.Errorf("failed to retrieve CBL Mariner Vulnerability Data: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	log.Println("Walking cbl mariner...")
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return xerrors.Errorf("failed to read directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if !(strings.HasPrefix(entry.Name(), "cbl-mariner-") && strings.HasSuffix(entry.Name(), ".xml")) {
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
	b, err := os.ReadFile(path)
	if err != nil {
		return xerrors.Errorf("failed to read file: %w", err)
	}

	var oval OvalDefinitions
	if err := xml.Unmarshal(b, &oval); err != nil {
		return xerrors.Errorf("failed to unmarshal xml: %w", err)
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
		// skip non-vulnerability definition
		if def.Class != "vulnerability" {
			continue
		}

		vulnID := def.Metadata.Reference.RefID

		if err := c.saveAdvisoryPerYear(filepath.Join(dirPath, definitionsDir), vulnID, def); err != nil {
			return xerrors.Errorf("failed to save advisory per year: %w", err)
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}

func (c Config) saveAdvisoryPerYear(dirName string, id string, def Definition) error {
	var year string
	if strings.HasPrefix(id, "CVE") {
		s := strings.Split(id, "-")
		if len(s) != 3 {
			log.Printf("invalid CVE-ID format: %s\n", id)
			return ErrInvalidCVEFormat
		}
		year = s[1]
	} else {
		log.Printf("discovered non-CVE-ID: %s\n", id)
		return ErrNonCVEID
	}
	yearDir := filepath.Join(dirName, year)
	if err := utils.Write(filepath.Join(yearDir, fmt.Sprintf("%s.json", id)), def); err != nil {
		return xerrors.Errorf("unable to write a JSON file: %w", err)
	}
	return nil
}
