package cvrf

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
	cvrfArchiveURL = "http://ftp.suse.com/pub/projects/security/cvrf.tar.bz2"
	cvrfDir        = "cvrf"
	suseDir        = "suse"
	retries        = 5
)

var fileRegexp = regexp.MustCompile(`^cvrf-(.*?)-`)

type Config struct {
	VulnListDir string
	URL         string
	AppFs       afero.Fs
}

func NewConfig() Config {
	return Config{
		VulnListDir: utils.VulnListDir(),
		URL:         cvrfArchiveURL,
		AppFs:       afero.NewOsFs(),
	}
}

func (c Config) Update() error {
	log.Print("Fetching SUSE CVRF archive...")

	return cvrfarchive.Walk(c.URL, retries, fileRegexp, func(e cvrfarchive.Entry) error {
		match := fileRegexp.FindStringSubmatch(e.Filename)
		osName := match[1]

		var cv Cvrf
		if err := xml.Unmarshal(e.Data, &cv); err != nil {
			return xerrors.Errorf("failed to decode SUSE XML (%s): %w", e.Filename, err)
		}

		dir := filepath.Join(cvrfDir, suseDir, osName)
		if err := c.saveCvrfPerYear(dir, cv.Tracking.ID, cv); err != nil {
			return xerrors.Errorf("failed to save CVRF: %w", err)
		}
		return nil
	})
}

func (c Config) saveCvrfPerYear(dirName string, cvrfID string, data Cvrf) error {
	s := strings.Split(cvrfID, "-")
	if len(s) < 4 {
		log.Printf("invalid CVRF-ID format: %s", cvrfID)
		return nil
	}

	year := strings.Split(s[2], ":")[0]
	if len(year) < 4 {
		log.Printf("invalid CVRF-ID format: %s", cvrfID)
		return nil
	}

	yearDir := filepath.Join(c.VulnListDir, dirName, year)
	fileName := fmt.Sprintf("%s.json", strings.Replace(cvrfID, ":", "-", 1))
	if err := utils.WriteJSON(c.AppFs, yearDir, fileName, data); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}
