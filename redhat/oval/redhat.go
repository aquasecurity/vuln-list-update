package oval

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"encoding/json"
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
	ovalDir = "oval"
	cpeDir  = "cpe"

	urlFormat    = "https://www.redhat.com/security/data/oval/v2/%s"
	retry        = 5
	pulpManifest = "PULP_MANIFEST"

	repoToCpeURL = "https://www.redhat.com/security/data/metrics/repository-to-cpe.json"

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
	VulnListDir  string
	URLFormat    string
	RepoToCpeURL string
	AppFs        afero.Fs
	Retry        int
}

func NewConfig() Config {
	return Config{
		VulnListDir:  utils.VulnListDir(),
		URLFormat:    urlFormat,
		RepoToCpeURL: repoToCpeURL,
		AppFs:        afero.NewOsFs(),
		Retry:        retry,
	}
}

func (c Config) Update() error {
	log.Println("Updating Red Hat mapping from repositories to CPE names...")
	if err := c.updateRepoToCpe(); err != nil {
		return xerrors.Errorf("unable to update repository-to-cpe.json: %w", err)
	}

	dirPath := filepath.Join(c.VulnListDir, ovalDir)
	log.Printf("Remove Red Hat OVAL v2 directory %s", dirPath)
	if err := os.RemoveAll(dirPath); err != nil {
		return xerrors.Errorf("failed to remove Red Hat OVAL v2 directory: %w", err)
	}

	log.Println("Fetching Red Hat OVAL v2 data...")
	filePaths, err := c.fetchOvalFilePaths()
	if err != nil {
		return xerrors.Errorf("failed to get oval file paths: %w", err)
	}
	for _, ovalFilePath := range filePaths {
		log.Printf("Fetching %s", ovalFilePath)
		if err := c.updateOVAL(ovalFilePath); err != nil {
			return xerrors.Errorf("failed to update Red Hat OVAL v2 json: %w", err)
		}
	}

	return nil
}

func (c Config) updateRepoToCpe() error {
	b, err := utils.FetchURL(c.RepoToCpeURL, "", c.Retry)
	if err != nil {
		return xerrors.Errorf("failed to get %s: %w", c.RepoToCpeURL, err)
	}

	var repoToCPE repositoryToCPE
	if err = json.Unmarshal(b, &repoToCPE); err != nil {
		return xerrors.Errorf("JSON parse error: %w", err)
	}

	mapping := map[string][]string{}
	for repo, cpes := range repoToCPE.Data {
		mapping[repo] = cpes.Cpes
	}

	dir := filepath.Join(c.VulnListDir, cpeDir)
	if err = utils.WriteJSON(c.AppFs, dir, "repository-to-cpe.json", mapping); err != nil {
		return xerrors.Errorf("JSON write error: %w", err)
	}

	return nil
}

func (c Config) updateOVAL(ovalFile string) error {
	// e.g. RHEL8/storage-gluster-3-including-unpatched.oval.xml.bz2
	if !strings.HasPrefix(ovalFile, "RHEL") {
		log.Printf("Skip %s", ovalFile)
		return nil
	}

	// e.g. RHEL8/storage-gluster-3-including-unpatched.oval.xml.bz2
	// => RHEL8/, storage-gluster-3-including-unpatched.oval.xml.bz2
	dir, file := path.Split(ovalFile)
	release := strings.TrimPrefix(path.Clean(dir), "RHEL")

	url := fmt.Sprintf(c.URLFormat, ovalFile)
	res, err := utils.FetchURL(url, "", c.Retry)
	if err != nil {
		return xerrors.Errorf("failed to fetch Red Hat OVAL v2: %w", err)
	}

	bzr := bzip2.NewReader(bytes.NewBuffer(res))
	var ovalroot OvalDefinitions
	if err := xml.NewDecoder(bzr).Decode(&ovalroot); err != nil {
		return xerrors.Errorf("failed to unmarshal Red Hat OVAL v2 XML: %w", err)
	}

	// e.g. storage-gluster-3-including-unpatched
	platform := strings.TrimSuffix(file, ".oval.xml.bz2")
	dirPath := filepath.Join(c.VulnListDir, ovalDir, release, platform)

	// write tests/tests.json file
	if err := utils.WriteJSON(c.AppFs, filepath.Join(dirPath, testsDir), "tests.json", ovalroot.Tests); err != nil {
		return xerrors.Errorf("failed to write tests: %w", err)
	}

	// write objects/objects.json file
	if err := utils.WriteJSON(c.AppFs, filepath.Join(dirPath, objectsDir), "objects.json", ovalroot.Objects); err != nil {
		return xerrors.Errorf("failed to write objects: %w", err)
	}

	// write states/states.json file
	if err := utils.WriteJSON(c.AppFs, filepath.Join(dirPath, statesDir), "states.json", ovalroot.States); err != nil {
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
	res, err := utils.FetchURL(fmt.Sprintf(c.URLFormat, pulpManifest), "", c.Retry)
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
		// skip if size is 0
		if ss[2] == "0" {
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
	if strings.HasPrefix(def.ID, "oval:com.redhat.unaffected:def") {
		fileFmt = "%s.unaffected.json"
	}

	yearDir := filepath.Join(dirName, year)
	if err := utils.WriteJSON(c.AppFs, yearDir, fmt.Sprintf(fileFmt, id), def); err != nil {
		return xerrors.Errorf("unable to write a JSON file: %w", err)
	}
	return nil
}
