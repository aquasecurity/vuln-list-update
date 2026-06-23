package echo

import (
	"github.com/aquasecurity/vuln-list-update/osv"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	osvURL = "https://advisory.echohq.com/osv/all.zip"
	osvDir = "echo-osv"

	// osEcosystem identifies Echo OS-level packages (e.g. distro packages).
	// These are already published via the legacy Echo updater, so they are
	// filtered out of the OSV output to avoid duplication. Application
	// ecosystems use the "Echo:<ecosystem>" form (e.g. "Echo:PyPI") and are
	// retained.
	osEcosystem = "Echo"
)

var osvEcosystems = map[string]osv.Ecosystem{
	"echo": {
		Dir:    osvDir,
		URL:    osvURL,
		Filter: IsOSPackage,
	},
}

// IsOSPackage reports whether an Affected entry refers to an Echo OS-level
// package (ecosystem exactly "Echo") and should be excluded from OSV output.
func IsOSPackage(a osv.Affected) bool {
	return a.Package.Ecosystem == osEcosystem
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
