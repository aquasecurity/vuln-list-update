package redhat

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
	urlFormat    = "https://www.redhat.com/security/data/oval/v2/%s"
	PulpManifest = "PULP_MANIFEST"

	testsDir       = "tests"
	objectsDir     = "objects"
	statesDir      = "states"
	definitionsDir = "definitions"
)

type debug struct {
	FileName string
	Criteria Criteria
}

var (
	releases = []string{"6", "7", "8"}

	ErrInvalidRHSAFormat = errors.New("invalid RHSA-ID format")
	ErrInvalidCVEFormat  = errors.New("invalid CVE-ID format")
)

type Config struct {
	VulnListDir string
	URLFormat   string
	AppFs       afero.Fs
	Retry       int
}

func NewConfig() Config {
	return Config{
		VulnListDir: utils.VulnListDir(),
		URLFormat:   urlFormat,
		AppFs:       afero.NewOsFs(),
		Retry:       retry,
	}
}

func (c Config) Update() error {
	log.Println("Fetching Red Hat OVAL data...")
	filepaths, err := c.fetchOvalFilePaths()
	if err != nil {
		return xerrors.Errorf("failed to get oval file paths: %w", err)
	}
	for _, ovalFilePath := range filepaths {
		log.Printf("Fetching %s", ovalFilePath)
		if err := c.update(ovalFilePath); err != nil {
			return err
		}
	}

	return nil
}

func (c Config) update(ovalFile string) error {
	// e.g. RHEL8/storage-gluster-3-including-unpatched.oval.xml.bz2
	if !strings.HasPrefix(ovalFile, "RHEL") {
		log.Printf("Skip %s", ovalFile)
		return nil
	}
	dir, file := path.Split(ovalFile)
	release := strings.TrimPrefix(dir, "RHEL")

	url := fmt.Sprintf(c.URLFormat, ovalFile)
	res, err := utils.FetchURL(url, "", c.Retry)
	if err != nil {
		return xerrors.Errorf("failed to fetch Red Hat OVALv2: %w", err)
	}

	bzr := bzip2.NewReader(bytes.NewBuffer(res))
	var ovalroot OvalDefinitions
	if err := xml.NewDecoder(bzr).Decode(&ovalroot); err != nil {
		return xerrors.Errorf("failed to unmarshal Red Hat OVAL V2 XML: %w", err)
	}

	// e.g. storage-gluster-3-including-unpatched
	platform := strings.TrimSuffix(file, ".oval.xml.bz2")
	dirPath := filepath.Join(c.VulnListDir, ovalDir, redhatDir, release, platform)

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

	advs := map[string][]string{}
	bar := pb.StartNew(len(ovalroot.Definitions.Definition))
	for _, def := range ovalroot.Definitions.Definition {
		if len(def.Metadata.References) == 0 {
			continue
		}

		// RHSA, CVE
		id := def.Metadata.References[0].RefID

		if err := c.saveAdvisoryPerYear(filepath.Join(dirPath, definitionsDir), id, def); err != nil {
			return xerrors.Errorf("failed to save advisory per year: %w", err)
		}

		bar.Increment()
	}
	bar.Finish()

	for id, adv := range advs {
		if len(adv) == 1 {
			continue
		}
		fmt.Printf("%s: %+v\n", id, adv)
	}

	return nil
}

func (c Config) fetchOvalFilePaths() ([]string, error) {
	res, err := utils.FetchURL(fmt.Sprintf(c.URLFormat, PulpManifest), "", c.Retry)
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
	var s []string
	if strings.HasPrefix(id, "CVE") {
		s = strings.Split(id, "-")
		if len(s) != 3 {
			log.Printf("invalid CVE-ID format: %s\n", id)
			return ErrInvalidCVEFormat
		}
	} else {
		// e.g. RHSA-2018:0094
		s = strings.Split(id, ":")
		if len(s) != 2 {
			log.Printf("invalid RHSA-ID format: %s\n", id)
			return ErrInvalidRHSAFormat
		}
		s = strings.Split(s[0], "-")
		if len(s) != 2 {
			log.Printf("invalid RHSA-ID format: %s\n", id)
			return ErrInvalidRHSAFormat

		}
	}

	filefmt := "%s.json"
	if strings.HasPrefix(def.Metadata.Title, "Unaffected components for:") {
		filefmt = "%s.unaffected.json"
	}

	yearDir := filepath.Join(dirName, s[1])
	if err := c.writeJson(yearDir, fmt.Sprintf(filefmt, id), def); err != nil {
		return err
	}
	return nil
}

func (c Config) writeJson(dirName, fileName string, data interface{}) error {
	if err := c.AppFs.MkdirAll(dirName, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to create a year dir: %w", err)
	}

	fs := utils.NewFs(c.AppFs)

	filePath := filepath.Join(dirName, fileName)
	if err := fs.WriteJSON(filePath, data); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}
