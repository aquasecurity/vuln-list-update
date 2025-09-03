package seal

import (
	"path/filepath"

	"github.com/aquasecurity/vuln-list-update/osv"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	securityTrackerURL = "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip"
	sealDir            = "seal"
)

// Seal uses single archive for all ecosystems, so we use a single ecosystem and single dir.
var ecosystems = map[string]string{"seal": ""}

type options struct {
	url string
	dir string
}

type option func(*options)

type Database struct {
	osv.Database
}

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

func NewSeal(opts ...option) Database {
	o := &options{
		url: securityTrackerURL,
		dir: filepath.Join(utils.VulnListDir(), sealDir),
	}

	for _, opt := range opts {
		opt(o)
	}

	db := osv.NewOsv(
		osv.WithURL(o.url),
		osv.WithDir(o.dir),
		osv.WithEcosystem(ecosystems),
	)

	return Database{
		Database: db,
	}
}

func (seal *Database) Update() error {
	return seal.Database.Update()
}
