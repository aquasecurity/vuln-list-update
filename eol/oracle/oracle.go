package oracle

import (
	"log"
	"path/filepath"
	"time"

	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"
)

const (
	distName = "Oracle Linux"
	dirPath  = "eol/oracle"
	fileName = "oracle.json"
)

var (
	eolDates = map[string]time.Time{
		// Source:
		// https://www.oracle.com/a/ocom/docs/elsp-lifetime-069338.pdf
		// https://community.oracle.com/docs/DOC-917964
		"3": time.Date(2011, 12, 31, 23, 59, 59, 0, time.UTC),
		"4": time.Date(2013, 12, 31, 23, 59, 59, 0, time.UTC),
		"5": time.Date(2017, 12, 31, 23, 59, 59, 0, time.UTC),
		"6": time.Date(2021, 3, 21, 23, 59, 59, 0, time.UTC),
		"7": time.Date(2024, 7, 23, 23, 59, 59, 0, time.UTC),
		"8": time.Date(2029, 7, 18, 23, 59, 59, 0, time.UTC),
	}
)

type options struct {
	vulnListDir string
	appFs       afero.Fs
}

type Config struct {
	*options
}

func NewConfig() Config {
	return Config{
		options: &options{
			vulnListDir: utils.VulnListDir(),
			appFs:       afero.NewOsFs(),
		},
	}
}

func (c Config) Name() string {
	return distName
}

func (c Config) Update() error {
	log.Printf("Fetching %s end-of-life dates...", distName)
	dir := filepath.Join(c.vulnListDir, dirPath)

	if err := utils.WriteJSON(c.appFs, dir, fileName, eolDates); err != nil {
		return xerrors.Errorf("failed to write %s under %s: %w", fileName, dirPath, err)
	}
	return nil
}
