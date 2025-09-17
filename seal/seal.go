package seal

import (
	"github.com/aquasecurity/vuln-list-update/osv"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	securityTrackerURL = "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip"
	sealDir            = "seal"
)

// Seal uses single archive for all ecosystems, so we use a single ecosystem and single dir.
var ecosystems = map[string]osv.Ecosystem{
	"seal": {
		Dir: sealDir,
		URL: securityTrackerURL,
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
