package echo

import (
	"github.com/aquasecurity/vuln-list-update/osv"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	osvURL = "https://advisory.echohq.com/osv/all.zip"
	osvDir = "echo-osv"
)

var osvEcosystems = map[string]osv.Ecosystem{
	"echo": {
		Dir: osvDir,
		URL: osvURL,
	},
}

type osvOptions struct {
	dir        string
	ecosystems map[string]osv.Ecosystem
}

type OSVOption func(*osvOptions)

func WithOSVDir(dir string) OSVOption {
	return func(opts *osvOptions) {
		opts.dir = dir
	}
}

func WithOSVEcosystems(ecosystems map[string]osv.Ecosystem) OSVOption {
	return func(opts *osvOptions) {
		opts.ecosystems = ecosystems
	}
}

func NewOSVUpdater(opts ...OSVOption) osv.Database {
	o := &osvOptions{
		dir:        utils.VulnListDir(),
		ecosystems: osvEcosystems,
	}

	for _, opt := range opts {
		opt(o)
	}

	return osv.NewDatabase(o.dir, o.ecosystems)
}
