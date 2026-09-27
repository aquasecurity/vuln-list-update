package csaf

import (
	"encoding/json"
	"log"
	"path/filepath"
	"strings"

	csaflib "github.com/csaf-poc/csaf_distribution/v3/csaf"
	"github.com/spf13/afero"

	susearchive "github.com/aquasecurity/vuln-list-update/suse"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	csafArchiveURL = "https://ftp.suse.com/pub/projects/security/csaf.tar.bz2"
	csafDir        = "csaf"
	suseDir        = "suse"
	retries        = 5
)

type Config struct {
	VulnListDir string
	URL         string
	AppFs       afero.Fs
}

func NewConfig() Config {
	return Config{
		VulnListDir: utils.VulnListDir(),
		URL:         csafArchiveURL,
		AppFs:       afero.NewOsFs(),
	}
}

func (c Config) Update() error {
	log.Print("Fetching SUSE CSAF archive...")

	var skipUnmarshal, skipValidate, skipNoTracking int
	updater := susearchive.Updater{
		URL:         c.URL,
		VulnListDir: c.VulnListDir,
		AppFs:       c.AppFs,
		Dir:         filepath.Join(csafDir, suseDir),
		Retries:     retries,
		OSName:      OsNameFromFilename,
	}

	err := updater.Update(func(filename string, data []byte) (string, any, error) {
		var adv csaflib.Advisory
		if err := json.Unmarshal(data, &adv); err != nil {
			skipUnmarshal++
			log.Printf("skip invalid CSAF json (%s): %v", filename, err)
			return "", nil, nil
		}

		if err := adv.Validate(); err != nil {
			skipValidate++
			log.Printf("skip invalid CSAF advisory (%s): %v", filename, err)
			return "", nil, nil
		}

		if adv.Document == nil || adv.Document.Tracking == nil || adv.Document.Tracking.ID == nil {
			skipNoTracking++
			log.Printf("skip advisory without tracking id (%s)", filename)
			return "", nil, nil
		}

		return string(*adv.Document.Tracking.ID), adv, nil
	})
	if err != nil {
		return err
	}

	log.Printf(
		"CSAF update finished: skipped unmarshal=%d validate=%d no_tracking=%d",
		skipUnmarshal, skipValidate, skipNoTracking,
	)
	return nil
}

// OsNameFromFilename takes the OS out of a CSAF filename:
// "opensuse-su-2019_0003-1.json" -> "opensuse".
func OsNameFromFilename(filename string) (string, bool) {
	// Every advisory ships with .sha256 and .asc sidecars, so skip everything that isn't JSON.
	if !strings.HasSuffix(filename, ".json") {
		return "", false
	}

	switch {
	case strings.HasPrefix(filename, "suse-su-"):
		return "suse", true
	case strings.HasPrefix(filename, "opensuse-su-"):
		return "opensuse", true
	default:
		return "", false
	}
}
