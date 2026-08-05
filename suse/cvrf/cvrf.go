package cvrf

import (
	"encoding/xml"
	"log"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	susearchive "github.com/aquasecurity/vuln-list-update/suse"
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

	return susearchive.WalkTarArchive(c.URL, retries, func(e susearchive.TarEntry) error {
		if !strings.HasSuffix(e.Filename, ".xml") {
			return nil
		}
		match := fileRegexp.FindStringSubmatch(e.Filename)
		if match == nil {
			return nil
		}
		osName := match[1]

		var cv Cvrf
		if err := xml.Unmarshal(e.Data, &cv); err != nil {
			return xerrors.Errorf("failed to decode SUSE XML (%s): %w", e.Filename, err)
		}

		dir := filepath.Join(cvrfDir, suseDir, osName)
		if err := susearchive.SavePerYear(c.VulnListDir, c.AppFs, dir, cv.Tracking.ID, cv); err != nil {
			log.Printf("skip CVRF advisory (%s): %v", e.Filename, err)
			return nil
		}
		return nil
	})
}
