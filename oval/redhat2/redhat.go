package redhat2

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/cheggaaa/pb"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	ovalDir      = "oval"
	redhatDir    = "redhat2"
	retry        = 5
	baseURL      = "https://www.redhat.com/security/data/oval/"
	pulpManifest = "PULP_MANIFEST"

	testsDir       = "tests"
	objectsDir     = "objects"
	statesDir      = "states"
	definitionsDir = "definitions"
)

var (
	ErrInvalidRHSAFormat = errors.New("invalid RHSA-ID format")
	ErrInvalidCVEFormat  = errors.New("invalid CVE-ID format")
)

type Config struct {
	vulnListDir string
	baseURL     string
	appFs       afero.Fs
	retry       int
}

type oval struct {
	release  string
	platform string
	url      string
}

func NewConfig() Config {
	return Config{
		vulnListDir: utils.VulnListDir(),
		baseURL:     baseURL,
		appFs:       afero.NewOsFs(),
		retry:       retry,
	}
}

func (c Config) Update() error {
	dirPath := filepath.Join(c.vulnListDir, ovalDir, redhatDir)
	log.Printf("Remove Red Hat OVAL v2 directory %s", dirPath)
	if err := os.RemoveAll(dirPath); err != nil {
		return xerrors.Errorf("failed to remove Red Hat OVAL v2 directory: %w", err)
	}

	log.Println("Fetching Red Hat OVAL data...")
	filePaths, err := c.fetchOvalFilePaths()
	if err != nil {
		return xerrors.Errorf("failed to get oval file paths: %w", err)
	}

	var ovals []oval
	for _, ovalFilePath := range filePaths {
		// e.g. RHEL8/storage-gluster-3-including-unpatched.oval.xml.bz2
		if !strings.HasPrefix(ovalFilePath, "RHEL") {
			log.Printf("Skip %s", ovalFilePath)
			return nil
		}
		ovals = append(ovals, c.parseOVALFileName(ovalFilePath))
	}

	// Only OVALv1 supports RHEL 5. Keep it for backward compatibility.
	ovals = append(ovals, oval{
		platform: "rhel5",
		release:  "5",
		url:      c.baseURL + "com.redhat.rhsa-RHEL5.xml.bz2",
	})

	for _, oval := range ovals {
		log.Printf("Fetching %s", oval.url)
		if err := c.update(oval); err != nil {
			return xerrors.Errorf("failed to update Red Hat OVAL v2: %w", err)
		}
	}

	return nil
}

func (c Config) parseOVALFileName(ovalFile string) oval {
	// e.g. RHEL8/storage-gluster-3-including-unpatched.oval.xml.bz2
	// => RHEL8/, storage-gluster-3-including-unpatched.oval.xml.bz2
	dir, file := path.Split(ovalFile)
	release := strings.TrimPrefix(path.Clean(dir), "RHEL")

	// e.g. storage-gluster-3-including-unpatched
	platform := strings.TrimSuffix(file, ".oval.xml.bz2")

	return oval{
		release:  release,
		platform: platform,
		url:      c.baseURL + path.Join("v2", ovalFile),
	}
}

func (c Config) update(oval oval) error {
	res, err := utils.FetchURL(oval.url, "", c.retry)
	if err != nil {
		return xerrors.Errorf("failed to fetch Red Hat OVAL v2: %w", err)
	}

	bzr := bzip2.NewReader(bytes.NewBuffer(res))
	var ovalroot OvalDefinitions
	if err := xml.NewDecoder(bzr).Decode(&ovalroot); err != nil {
		return xerrors.Errorf("failed to unmarshal Red Hat OVAL v2 XML: %w", err)
	}

	dirPath := filepath.Join(c.vulnListDir, ovalDir, redhatDir, oval.release, oval.platform)

	// write tests/tests.json file
	if err := c.writeJson(filepath.Join(dirPath, testsDir), "tests.json", ovalroot.Tests); err != nil {
		return xerrors.Errorf("failed to write tests: %w", err)
	}

	// write objects/objects.json file
	if err := c.writeJson(filepath.Join(dirPath, objectsDir), "objects.json", ovalroot.Objects); err != nil {
		return xerrors.Errorf("failed to write objects: %w", err)
	}

	// write states/states.json file
	if err := c.writeJson(filepath.Join(dirPath, statesDir), "states.json", ovalroot.States); err != nil {
		return xerrors.Errorf("failed to write states: %w", err)
	}

	// write definitions
	bar := pb.StartNew(len(ovalroot.Definitions.Definition))
	for _, def := range ovalroot.Definitions.Definition {
		if len(def.Metadata.References) == 0 {
			continue
		}

		// RHSA-ID or CVE-ID
		vulnID := def.Metadata.References[0].RefID
		for _, ref := range def.Metadata.References {
			if strings.HasPrefix(ref.RefID, "RHSA-") {
				vulnID = ref.RefID
			}
		}

		if err := c.saveAdvisoryPerYear(filepath.Join(dirPath, definitionsDir), vulnID, def); err != nil {
			return xerrors.Errorf("failed to save advisory per year: %w", err)
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}

func (c Config) fetchOvalFilePaths() ([]string, error) {
	res, err := utils.FetchURL(c.baseURL+path.Join("v2", pulpManifest), "", c.retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch PULP_MANIFEST: %w", err)
	}

	var ovalFilePaths []string
	scanner := bufio.NewScanner(bytes.NewReader(res))
	for scanner.Scan() {
		ss := strings.Split(scanner.Text(), ",")
		if len(ss) < 3 {
			return nil, xerrors.Errorf("failed to parse PULP_MANIFEST: %w", err)
		}
		if !strings.Contains(ss[0], "including-unpatched") {
			continue
		}

		ovalFilePaths = append(ovalFilePaths, ss[0])
	}
	return ovalFilePaths, nil
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
		// e.g. RHSA-2018:0094
		s := strings.Split(id, ":")
		if len(s) != 2 {
			log.Printf("invalid RHSA-ID format: %s\n", id)
			return ErrInvalidRHSAFormat
		}
		s = strings.Split(s[0], "-")
		if len(s) != 2 {
			log.Printf("invalid RHSA-ID format: %s\n", id)
			return ErrInvalidRHSAFormat
		}
		year = s[1]
	}

	fileFmt := "%s.json"
	if strings.HasPrefix(def.Metadata.Title, "Unaffected components for:") {
		fileFmt = "%s.unaffected.json"
	}

	yearDir := filepath.Join(dirName, year)
	if err := c.writeJson(yearDir, fmt.Sprintf(fileFmt, id), def); err != nil {
		return xerrors.Errorf("unable to write a JSON file: %w", err)
	}
	return nil
}

func (c Config) writeJson(dirName, fileName string, data interface{}) error {
	if err := c.appFs.MkdirAll(dirName, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to create a year dir: %w", err)
	}

	fs := utils.NewFs(c.appFs)

	filePath := filepath.Join(dirName, fileName)
	if err := fs.WriteJSON(filePath, data); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}
