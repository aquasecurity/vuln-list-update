package wolfi

import (
	"log"
	"net/url"
	"path/filepath"

	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/alpine"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	wolfiDir = "wolfi"
	repoURL  = "https://packages.wolfi.dev/os"
)

type option func(c *Updater)

func WithVulnListDir(v string) option {
	return func(c *Updater) { c.vulnListDir = v }
}

func WithAppFs(v afero.Fs) option {
	return func(c *Updater) { c.appFs = v }
}

type Updater struct {
	vulnListDir string
	appFs       afero.Fs
	baseURL     *url.URL
}

func NewUpdater(options ...option) *Updater {
	u, _ := url.Parse(repoURL)
	updater := &Updater{
		vulnListDir: utils.VulnListDir(),
		appFs:       afero.NewOsFs(),
		baseURL:     u,
	}
	for _, option := range options {
		option(updater)
	}

	return updater
}

func (updater *Updater) Update() error {
	dir := filepath.Join(updater.vulnListDir, wolfiDir)
	log.Printf("Remove Alpine directory %s", dir)
	if err := updater.appFs.RemoveAll(dir); err != nil {
		return xerrors.Errorf("failed to remove Wolfi directory: %w", err)
	}
	if err := updater.appFs.MkdirAll(dir, 0755); err != nil {
		return xerrors.Errorf("mkdir error: %w", err)
	}

	log.Println("Fetching Wolfi data...")

	alpineUpdater := alpine.NewUpdater(
		alpine.WithBaseURL(updater.baseURL),
		alpine.WithAdvisoryDir(wolfiDir),
		alpine.WithAppFs(updater.appFs))
	return alpineUpdater.Save("", "security.json")
}
