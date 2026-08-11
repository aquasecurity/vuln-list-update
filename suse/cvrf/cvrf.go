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

	updater := susearchive.Updater{
		URL:         c.URL,
		VulnListDir: c.VulnListDir,
		AppFs:       c.AppFs,
		Dir:         filepath.Join(cvrfDir, suseDir),
		Retries:     retries,
		OSName:      osNameFromFilename,
	}

	return updater.Update(func(filename string, data []byte) (string, any, error) {
		var cv Cvrf
		if err := xml.Unmarshal(data, &cv); err != nil {
			return "", nil, xerrors.Errorf("failed to decode SUSE XML (%s): %w", filename, err)
		}
		return cv.Tracking.ID, cv, nil
	})
}

// osNameFromFilename takes the OS out of a CVRF filename:
// "cvrf-opensuse-su-2015-0225-1.xml" -> "opensuse".
func osNameFromFilename(filename string) (string, bool) {
	// The archive contains non-XML files (e.g. LICENSE), so skip them.
	if !strings.HasSuffix(filename, ".xml") {
		return "", false
	}

	match := fileRegexp.FindStringSubmatch(filename)
	if match == nil {
		return "", false
	}
	return match[1], true
}
