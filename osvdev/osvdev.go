// Package osvdev provides OSV vulnerability data collection from osv.dev
// (osv-vulnerabilities.storage.googleapis.com).
//
// This package implements a specific data source for OSV.dev's vulnerability database,
// which aggregates vulnerability data from multiple ecosystems including:
// - PyPI (Python packages)
// - Go (Go modules)
// - crates.io (Rust crates)
// - Julia (Julia packages)
//
// It uses the generic osv package to handle OSV format processing and provides
// OSV.dev-specific configuration such as default URLs and directory structure.
//
// This is the recommended replacement for the legacy "osv" target in main.go.
package osvdev

import (
	"path/filepath"

	"github.com/aquasecurity/vuln-list-update/osv"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	osvdevDir = "osv"
)

var defaultEcosystems = map[string]osv.Ecosystem{
	"PyPI": {
		Dir: "python",
		URL: "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
	},
	"Go": {
		Dir: "go",
		URL: "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip",
	},
	"crates.io": {
		Dir: "rust",
		URL: "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip",
	},
	"Julia": {
		Dir: "julia",
		URL: "https://osv-vulnerabilities.storage.googleapis.com/Julia/all.zip",
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
		dir:        filepath.Join(utils.VulnListDir(), osvdevDir),
		ecosystems: defaultEcosystems,
	}
	for _, opt := range opts {
		opt(o)
	}

	return osv.NewDatabase(o.dir, o.ecosystems)
}
