// Package rootio provides OSV vulnerability data collection from Root.io's
// external OSV feed (https://api.root.io/external/osv/all.zip).
//
// Root.io publishes a single archive containing advisories across all
// supported ecosystems, so this package configures the generic osv package
// with a single ecosystem pointing at that archive.
package rootio

import (
	"path/filepath"

	"github.com/aquasecurity/vuln-list-update/osv"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	rootioDir = "rootio"
	feedURL   = "https://api.root.io/external/osv/all.zip"
)

var defaultEcosystems = map[string]osv.Ecosystem{
	"Root": {
		Dir: "",
		URL: feedURL,
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

func NewDatabase(opts ...Option) osv.Database {
	o := &options{
		dir:        filepath.Join(utils.VulnListDir(), rootioDir),
		ecosystems: defaultEcosystems,
	}
	for _, opt := range opts {
		opt(o)
	}

	return osv.NewDatabase(o.dir, o.ecosystems)
}
