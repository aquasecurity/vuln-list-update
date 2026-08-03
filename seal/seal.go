package seal

import (
	"path/filepath"

	"github.com/aquasecurity/vuln-list-update/osv"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	// renamedFeedURL holds advisories for packages that Seal renames
	// (e.g. "seal-requests", "@seal-security/ajv").
	renamedFeedURL = "https://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip"
	// noPrefixFeedURL holds advisories for packages that keep their original
	// name and only change the version (e.g. "requests" at "2.14.2+sp1").
	noPrefixFeedURL = "https://vulnfeed.sealsecurity.io/v1/osv/vulnerabilities.zip"
	sealDir         = "seal"
)

// The two feeds are stored in their own subdirectories so they don't overwrite
// each other when the osv package clears a directory before each update. Trivy
// reads the whole seal/ tree, so the split is transparent to it.
var ecosystems = map[string]osv.Ecosystem{
	"seal-renamed": {
		Dir: filepath.Join(sealDir, "renamed"),
		URL: renamedFeedURL,
	},
	"seal-noprefix": {
		Dir: filepath.Join(sealDir, "noprefix"),
		URL: noPrefixFeedURL,
	},
}

type options struct {
	dir        string
	ecosystems map[string]osv.Ecosystem
}

type Option func(*options)

func WithDir(dir string) Option {
	return func(opts *options) {
		opts.dir = dir
	}
}

func WithEcosystems(ecosystems map[string]osv.Ecosystem) Option {
	return func(opts *options) {
		opts.ecosystems = ecosystems
	}
}

func NewSeal(opts ...Option) osv.Database {
	o := &options{
		dir:        utils.VulnListDir(),
		ecosystems: ecosystems,
	}

	for _, opt := range opts {
		opt(o)
	}

	return osv.NewDatabase(o.dir, o.ecosystems)
}
