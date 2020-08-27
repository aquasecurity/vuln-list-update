package redhat

import (
	"bytes"
	"compress/bzip2"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/afero"
	"golang.org/x/xerrors"
	"gopkg.in/cheggaaa/pb.v1"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	ovalDir   = "oval"
	redhatDir = "redhat"

	classVulnerability = "vulnerability"

	urlFormat                   = "https://www.redhat.com/security/data/oval/v2/RHEL%s/rhel-%s.oval.xml.bz2"
	urlFormatIncludingUnpatched = "https://www.redhat.com/security/data/oval/v2/beta/RHEL%s/rhel-%s-including-unpatched.oval.xml.bz2"

	retry = 5
)

var (
	regexCVEFormat               = regexp.MustCompile(`CVE-\d{4,}-\d{4,}`)
	releases                     = []string{"6"}
	releasesIncludingUnpatchVuln = []string{"7", "8"}
)

var (
	ErrInvalidRHSAFormat = errors.New("invalid RHSA-ID format")
	ErrInvalidCVEFormat  = errors.New("invalid CVE-ID format")
)

type Config struct {
	VulnListDir                 string
	URLFormat                   string
	URLFormatIncludingUnpatched string
	AppFs                       afero.Fs
	Retry                       int
}

func NewConfig() Config {
	return Config{
		VulnListDir:                 utils.VulnListDir(),
		URLFormat:                   urlFormat,
		URLFormatIncludingUnpatched: urlFormatIncludingUnpatched,
		AppFs:                       afero.NewOsFs(),
		Retry:                       retry,
	}
}

func (c Config) Update() error {
	log.Println("Fetching Red Hat OVAL data...")
	for _, release := range releases {
		if err := c.update(release, c.URLFormat); err != nil {
			return err
		}
	}
	for _, release := range releasesIncludingUnpatchVuln {
		if err := c.update(release, c.URLFormatIncludingUnpatched); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) update(release string, formattedURL string) error {
	url := fmt.Sprintf(formattedURL, release, release)
	res, err := utils.FetchURL(url, "", c.Retry)
	if err != nil {
		return xerrors.Errorf("failed to fetch Red Hat OVAL: %w", err)
	}

	bzr := bzip2.NewReader(bytes.NewBuffer(res))

	log.Printf("Updating Red Hat %s OVAL data...\n", release)
	ovalroot := Root{}
	if err = xml.NewDecoder(bzr).Decode(&ovalroot); err != nil {
		return xerrors.Errorf("failed to unmarshal Red Hat OVAL XML: %w", err)
	}

	dir := filepath.Join(ovalDir, redhatDir, release)
	bar := pb.StartNew(len(ovalroot.Definitions.Definitions))
	for _, def := range ovalroot.Definitions.Definitions {
		if def.Class == classVulnerability {
			if err = c.saveCVEPerYear(dir, def.References[0].RefID, def); err != nil {
				switch err {
				case ErrInvalidCVEFormat:
					continue
				default:
					return xerrors.Errorf("unable to save CVE: %w", err)
				}
			}
			continue
		}
		titles := strings.Fields(def.Title)
		title := strings.Trim(titles[0], ":")
		if err = c.saveRHSAPerYear(dir, title, def); err != nil {
			switch err {
			case ErrInvalidRHSAFormat:
				continue
			default:
				return xerrors.Errorf("unable to save RHEL advisory: %w", err)
			}
		}
		bar.Increment()
	}
	bar.Finish()
	return nil
}

func (c Config) saveRHSAPerYear(dirName string, rhsaID string, data interface{}) error {
	// e.g. RHSA-2018:0094
	s := strings.Split(rhsaID, ":")
	if len(s) != 2 {
		log.Printf("invalid RHSA-ID format: %s\n", rhsaID)
		return ErrInvalidRHSAFormat
	}
	s = strings.Split(s[0], "-")
	if len(s) != 2 {
		log.Printf("invalid RHSA-ID format: %s\n", rhsaID)
		return ErrInvalidRHSAFormat
	}

	yearDir := filepath.Join(c.VulnListDir, dirName, s[1])
	if err := c.AppFs.MkdirAll(yearDir, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to create a year dir: %w", err)
	}

	filePath := filepath.Join(yearDir, fmt.Sprintf("%s.json", rhsaID))
	fs := utils.NewFs(c.AppFs)
	if err := fs.WriteJSON(filePath, data); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}

func (c Config) saveCVEPerYear(dirName string, cveID string, data interface{}) error {
	// e.g. CVE-2013-7488
	cveIDs := regexCVEFormat.FindStringSubmatch(cveID)
	if len(cveIDs) < 1 {
		log.Printf("invalid CVE-ID format: %s\n", cveID)
		return ErrInvalidCVEFormat
	}
	cveID = cveIDs[0]
	s := strings.Split(cveID, "-")
	if len(s) != 3 {
		log.Printf("invalid CVE-ID format: %s\n", cveID)
		return ErrInvalidCVEFormat
	}
	yearDir := filepath.Join(c.VulnListDir, dirName, s[1])
	if err := c.AppFs.MkdirAll(yearDir, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to create a year dir: %w", err)
	}
	filePath := filepath.Join(yearDir, fmt.Sprintf("%s.json", cveID))
	fs := utils.NewFs(c.AppFs)
	if err := fs.WriteJSON(filePath, data); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}
