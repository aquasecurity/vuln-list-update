package csaf

import (
	"encoding/json"
	"log"
	"path/filepath"
	"strings"

	"github.com/gocsaf/csaf/v3/csaf"
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

	var saved, skipInvalidJSON, skipNoTracking, nonConformant int
	updater := susearchive.Updater{
		URL:         c.URL,
		VulnListDir: c.VulnListDir,
		AppFs:       c.AppFs,
		Dir:         filepath.Join(csafDir, suseDir),
		Retries:     retries,
		OSName:      OsNameFromFilename,
	}

	err := updater.Update(func(filename string, data []byte) (string, any, error) {
		var header advisoryHeader
		if err := json.Unmarshal(data, &header); err != nil {
			skipInvalidJSON++
			log.Printf("skip invalid JSON (%s): %v", filename, err)
			return "", nil, nil
		}

		if header.Document.Tracking.ID == "" {
			skipNoTracking++
			log.Printf("skip advisory without tracking id (%s)", filename)
			return "", nil, nil
		}

		// The SUSE feed is not always schema-conformant (e.g. unescaped characters in CPEs),
		// and strict CSAF parsing rejects the whole document in that case. The advisory is still
		// stored as-is, like every other source, and filtering is left to consumers (trivy-db).
		if err := validate(data); err != nil {
			nonConformant++
			log.Printf("non-conformant CSAF advisory, saved as-is (%s): %v", filename, err)
		}

		saved++
		return header.Document.Tracking.ID, json.RawMessage(data), nil
	})
	if err != nil {
		return err
	}

	log.Printf("SUSE CSAF update finished: saved=%d (non-conformant=%d), skipped invalid_json=%d no_tracking_id=%d",
		saved, nonConformant, skipInvalidJSON, skipNoTracking)
	return nil
}

// validate checks the advisory against CSAF 2.0 schema rules from gocsaf/csaf.
func validate(data []byte) error {
	var adv csaf.Advisory
	if err := json.Unmarshal(data, &adv); err != nil {
		return err
	}
	return adv.Validate()
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
