package csaf

import (
	"encoding/json"
	"log"
	"path/filepath"
	"strings"

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

// advisoryHeader holds the only fields the updater needs to place an advisory on disk.
type advisoryHeader struct {
	Document struct {
		Tracking struct {
			ID string `json:"id"`
		} `json:"tracking"`
	} `json:"document"`
}

func (c Config) Update() error {
	log.Print("Fetching SUSE CSAF archive...")

	updater := susearchive.Updater{
		URL:         c.URL,
		VulnListDir: c.VulnListDir,
		AppFs:       c.AppFs,
		Dir:         filepath.Join(csafDir, suseDir),
		Retries:     retries,
		OSName:      OsNameFromFilename,
	}

	return updater.Update(func(filename string, data []byte) (string, any, error) {
		var header advisoryHeader
		if err := json.Unmarshal(data, &header); err != nil {
			return "", nil, nil
		}

		// The tracking ID is required to determine the release year and target filename on disk.
		if header.Document.Tracking.ID == "" {
			return "", nil, nil
		}

		return header.Document.Tracking.ID, json.RawMessage(data), nil
	})
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
