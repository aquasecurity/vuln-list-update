package wolfi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	wolfiDir     = "wolfi"
	secdbURLBase = "https://packages.wolfi.dev"
	secdbURLPath = "os/security.json"
	retry        = 3
)

type Updater struct {
	vulnListDir string
	appFs       afero.Fs
	baseURL     *url.URL
	retry       int
}

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

func WithRetry(v int) option {
	return func(c *Updater) { c.retry = v }
}

func NewUpdater(options ...option) *Updater {
	u, _ := url.Parse(secdbURLBase)
	updater := &Updater{
		vulnListDir: utils.VulnListDir(),
		appFs:       afero.NewOsFs(),
		baseURL:     u,
		retry:       retry,
	}
	for _, option := range options {
		option(updater)
	}

	return updater
}

func (u Updater) Update() (err error) {
	dir := filepath.Join(u.vulnListDir, wolfiDir)
	log.Printf("Remove Wolfi directory %s", dir)
	if err := u.appFs.RemoveAll(dir); err != nil {
		return xerrors.Errorf("failed to remove Wolfi directory: %w", err)
	}
	if err := u.appFs.MkdirAll(dir, 0755); err != nil {
		return err
	}

	log.Println("Fetching Wolfi data...")
	if err = u.save(); err != nil {
		return err
	}

	return nil
}

func (u Updater) traverse(url url.URL) ([]string, error) {
	b, err := utils.FetchURL(url.String(), "", u.retry)
	if err != nil {
		return nil, err
	}

	d, err := goquery.NewDocumentFromReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	var files []string
	d.Find("a").Each(func(i int, selection *goquery.Selection) {
		if !strings.HasSuffix(selection.Text(), ".json") {
			return
		}
		files = append(files, selection.Text())
	})
	return files, nil
}

func (u Updater) save() error {
	secdbURL := *u.baseURL
	secdbURL.Path = secdbURLPath
	b, err := utils.FetchURL(secdbURL.String(), "", u.retry)
	if err != nil {
		return err
	}

	var secdb secdb
	if err = json.Unmarshal(b, &secdb); err != nil {
		return err
	}

	for _, pkg := range secdb.Packages {
		if err = u.savePkg(secdb, pkg.Pkg); err != nil {
			return err
		}
	}

	return nil
}

func (u Updater) savePkg(secdb secdb, pkg pkg) error {
	advisory := advisory{
		Name:          pkg.Name,
		Secfixes:      pkg.Secfixes,
		Apkurl:        secdb.Apkurl,
		Archs:         secdb.Archs,
		Urlprefix:     secdb.Urlprefix,
		Reponame:      secdb.Reponame,
		Distroversion: secdb.Distroversion,
	}

	dir := filepath.Join(u.vulnListDir, wolfiDir, secdb.Reponame)
	file := fmt.Sprintf("%s.json", pkg.Name)
	if err := utils.WriteJSON(u.appFs, dir, file, advisory); err != nil {
		return xerrors.Errorf("failed to write %s under %s: %w", file, dir, err)
	}

	return nil
}
