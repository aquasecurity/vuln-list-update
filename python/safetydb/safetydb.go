package safetydb

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	vulndbURL = "https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json"
	vulndbDir = "python/safety-db"
	retry     = 5
)

type options struct {
	url string
	dir string
}

type option func(*options)

func WithURL(url string) option {
	return func(opts *options) {
		opts.url = url
	}
}

func WithDir(dir string) option {
	return func(opts *options) {
		opts.dir = dir
	}
}

type VulnDBSource struct {
	options
}

func NewVulnDB(opts ...option) VulnDBSource {
	o := &options{
		url: vulndbURL,
		dir: filepath.Join(utils.VulnListDir(), vulndbDir),
	}

	for _, opt := range opts {
		opt(o)
	}

	return VulnDBSource{options: *o}
}

func (c VulnDBSource) Update() error {
	log.Println("Fetching Python Safety Database...")

	b, err := utils.FetchURL(c.url, "", retry)
	if err != nil {
		return xerrors.Errorf("failed to fetch python-safetydb: %w", err)
	}

	advisoryDB := AdvisoryDB{}
	if err = json.Unmarshal(b, &advisoryDB); err != nil {
		return xerrors.Errorf("failed to decode python-safetydb response: %w", err)
	}

	// Parse package advisories
	log.Println("Saving Python Safety Database...")
	for pkgName, advisories := range advisoryDB {
		if err := c.save(pkgName, advisories); err != nil {
			return xerrors.Errorf("failed to save python-safetydb advisories: %w", err)
		}
	}
	return nil
}

func (c VulnDBSource) save(packageName string, advisories []RawAdvisory) error {
	for _, advisory := range advisories {
		pkgDir := filepath.Join(c.dir, packageName)
		if err := os.MkdirAll(pkgDir, os.ModePerm); err != nil {
			return xerrors.Errorf("failed to create python-safetydb directory: %w", err)
		}

		filePath := filepath.Join(pkgDir, advisory.ID+".json")
		if err := utils.WriteWithoutHTMLEscape(filePath, advisory); err != nil {
			return xerrors.Errorf("failed to save python-safetydb detail: %w", err)
		}
	}
	return nil
}
