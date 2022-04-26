package photon

import (
	"log"
	"path/filepath"
	"time"

	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"
)

const (
	distName = "Photon OS"
	dirPath  = "eol/photon"
	fileName = "photon.json"
)

var (
	eolDates = map[string]time.Time{
		"1.0": time.Date(2022, 2, 28, 23, 59, 59, 0, time.UTC),
		"2.0": time.Date(2022, 12, 31, 23, 59, 59, 0, time.UTC),
		// The following versions don't have the EOL dates yet.
		// See https://blogs.vmware.com/vsphere/2022/01/photon-1-x-end-of-support-announcement.html
		"3.0": time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC),
		"4.0": time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
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
