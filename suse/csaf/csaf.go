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

type updateStats struct {
	matched        int
	saved          int
	skipFilename   int
	skipUnmarshal  int
	skipValidate   int
	skipNoTracking int
	skipBadID      int
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

	var stats updateStats
	err := susearchive.WalkTarArchive(c.URL, retries, func(e susearchive.TarEntry) error {
		if !strings.HasSuffix(e.Filename, ".json") {
			return nil
		}
		stats.matched++

		osName, ok := osNameFromFilename(e.Filename)
		if !ok {
			stats.skipFilename++
			log.Printf("skip %s: unexpected filename", e.Filename)
			return nil
		}

		var adv csaflib.Advisory
		if err := json.Unmarshal(e.Data, &adv); err != nil {
			stats.skipUnmarshal++
			log.Printf("skip invalid CSAF json (%s): %v", e.Filename, err)
			return nil
		}

		if err := adv.Validate(); err != nil {
			stats.skipValidate++
			log.Printf("skip invalid CSAF advisory (%s): %v", e.Filename, err)
			return nil
		}

		if adv.Document == nil || adv.Document.Tracking == nil || adv.Document.Tracking.ID == nil {
			stats.skipNoTracking++
			log.Printf("skip advisory without tracking id (%s)", e.Filename)
			return nil
		}

		advisoryID := string(*adv.Document.Tracking.ID)
		dir := filepath.Join(csafDir, suseDir, osName)
		if err := susearchive.SavePerYear(c.VulnListDir, c.AppFs, dir, advisoryID, adv); err != nil {
			stats.skipBadID++
			log.Printf("skip advisory (%s): %v", e.Filename, err)
			return nil
		}
		stats.saved++
		return nil
	})
	if err != nil {
		return err
	}

	log.Printf(
		"CSAF update summary: matched=%d saved=%d skipped=%d (filename=%d unmarshal=%d validate=%d no_tracking=%d bad_id=%d)",
		stats.matched, stats.saved,
		stats.skipFilename+stats.skipUnmarshal+stats.skipValidate+stats.skipNoTracking+stats.skipBadID,
		stats.skipFilename, stats.skipUnmarshal, stats.skipValidate, stats.skipNoTracking, stats.skipBadID,
	)
	return nil
}

func osNameFromFilename(filename string) (string, bool) {
	switch {
	case strings.HasPrefix(filename, "suse-su-"):
		return "suse", true
	case strings.HasPrefix(filename, "opensuse-su-"):
		return "opensuse", true
	default:
		return "", false
	}
}
