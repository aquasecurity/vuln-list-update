// Package osvdev provides OSV vulnerability data collection from osv.dev
// (osv-vulnerabilities.storage.googleapis.com).
//
// This package implements a specific data source for OSV.dev's vulnerability database,
// which aggregates vulnerability data from multiple ecosystems including:
// - PyPI (Python packages)
// - Go (Go modules)
// - crates.io (Rust crates)
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
	securityTrackerURL = "https://osv-vulnerabilities.storage.googleapis.com/%s/all.zip"
	osvdevDir          = "osv"
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
}

type options struct {
	url        string
	dir        string
	ecosystems map[string]osv.Ecosystem
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

func WithEcosystem(ecosystemDir map[string]string) option {
	// Convert old-style map to new Ecosystem struct for backward compatibility
	ecosystems := make(map[string]osv.Ecosystem)
	for name, dir := range ecosystemDir {
		ecosystems[name] = osv.Ecosystem{
			Dir: dir,
		}
	}
	return func(opts *options) {
		opts.ecosystems = ecosystems
	}
}

func WithEcosystems(ecosystems map[string]osv.Ecosystem) option {
	return func(opts *options) {
		opts.ecosystems = ecosystems
	}
}

func NewDatabase(opts ...option) osv.Database {
	o := &options{
		url:        securityTrackerURL,
		dir:        filepath.Join(utils.VulnListDir(), osvdevDir),
		ecosystems: defaultEcosystems,
	}
	for _, opt := range opts {
		opt(o)
	}

	return osv.NewDatabase(o.dir, o.ecosystems)
}
