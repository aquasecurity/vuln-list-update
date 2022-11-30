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
	wolfiDir     = "wolfi"
	secdbURLBase = "https://packages.wolfi.dev"
	secdbURLPath = "os/security.json"
)

type option func(c *Updater)

func WithVulnListDir(v string) option {
	return func(c *Updater) { c.vulnListDir = v }
}

func WithAppFs(v afero.Fs) option {
	return func(c *Updater) { c.appFs = v }
}

func WithBaseURL(v *url.URL) option {
	return func(c *Updater) { c.baseURL = v }
}

type Updater struct {
	vulnListDir string
	appFs       afero.Fs
	baseURL     *url.URL
}

func NewUpdater(options ...option) *Updater {
	u, _ := url.Parse(secdbURLBase)
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

func (u *Updater) Update() error {
	dir := filepath.Join(u.vulnListDir, wolfiDir)
	log.Printf("Remove Wolfi directory %s", dir)
	if err := u.appFs.RemoveAll(dir); err != nil {
		return xerrors.Errorf("failed to remove Wolfi directory: %w", err)
	}
	if err := u.appFs.MkdirAll(dir, 0755); err != nil {
		return xerrors.Errorf("Wolfi mkdir error: %w", err)
	}

	log.Println("Fetching Wolfi data...")

	alpineUpdater := alpine.NewUpdater(
		alpine.WithBaseURL(u.baseURL),
		alpine.WithVulnListDir(u.vulnListDir),
		alpine.WithAdvisoryDir(wolfiDir),
		alpine.WithAppFs(u.appFs))
	return alpineUpdater.Save("", secdbURLPath)
}
