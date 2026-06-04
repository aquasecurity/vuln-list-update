package cvrfcve

import (
	"encoding/xml"
	"fmt"
	"log"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/suse/cvrfarchive"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	cvrfCVEArchiveURL = "http://ftp.suse.com/pub/projects/security/cvrf-cve.tar.bz2"
	cvrfDir           = "cvrf"
	suseCVEDir        = "suse-cves"
	retries           = 5
)

var fileRegexp = regexp.MustCompile(`^cvrf-(CVE-\d{4}-\d+)\.xml$`)

type Config struct {
	VulnListDir string
	URL         string
	AppFs       afero.Fs
}

func NewConfig() Config {
	return Config{
		VulnListDir: utils.VulnListDir(),
		URL:         cvrfCVEArchiveURL,
		AppFs:       afero.NewOsFs(),
	}
}

func (c Config) Update() error {
	log.Print("Fetching SUSE CVE CVRF archive...")

	return cvrfarchive.Walk(c.URL, retries, fileRegexp, func(e cvrfarchive.Entry) error {
		// CVE ID is taken from the file name, already validated by fileRegexp.
		cveID := fileRegexp.FindStringSubmatch(e.Filename)[1]

		var cv Cvrf
		if err := xml.Unmarshal(e.Data, &cv); err != nil {
			return xerrors.Errorf("failed to decode SUSE CVE CVRF XML (%s): %w", e.Filename, err)
		}

		return c.saveCVEPerYear(cveID, cv)
	})
}

func (c Config) saveCVEPerYear(cveID string, data Cvrf) error {
	year := strings.Split(cveID, "-")[1]
	yearDir := filepath.Join(c.VulnListDir, cvrfDir, suseCVEDir, year)
	fileName := fmt.Sprintf("%s.json", cveID)
	if err := utils.WriteJSON(c.AppFs, yearDir, fileName, data); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}
