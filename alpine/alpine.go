package alpine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"path"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	alpineDir = "alpine"
	repoURL   = "https://secdb.alpinelinux.org/"
	retry     = 3
)

type Updater struct {
	vulnListDir string
	advisoryDir string
	appFs       afero.Fs
	baseURL     *url.URL
	retry       int
}

type option func(c *Updater)

func WithVulnListDir(v string) option {
	return func(c *Updater) { c.vulnListDir = v }
}

func WithAdvisoryDir(s string) option {
	return func(c *Updater) { c.advisoryDir = s }
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
	u, _ := url.Parse(repoURL)
	updater := &Updater{
		vulnListDir: utils.VulnListDir(),
		advisoryDir: alpineDir,
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
	dir := filepath.Join(u.vulnListDir, u.advisoryDir)
	log.Printf("Remove Alpine directory %s", dir)
	if err := u.appFs.RemoveAll(dir); err != nil {
		return xerrors.Errorf("failed to remove Alpine directory: %w", err)
	}
	if err := u.appFs.MkdirAll(dir, 0755); err != nil {
		return err
	}

	log.Println("Fetching Alpine data...")
	b, err := utils.FetchURL(u.baseURL.String(), "", u.retry)
	if err != nil {
		return err
	}

	d, err := goquery.NewDocumentFromReader(bytes.NewReader(b))
	if err != nil {
		return err
	}

	var releases []string
	d.Find("a").Each(func(i int, selection *goquery.Selection) {
		release := selection.Text()
		if !strings.HasPrefix(release, "v") && !strings.HasPrefix(release, "edge") {
			return
		}
		releases = append(releases, release)
	})

	for _, release := range releases {
		releaseURL := *u.baseURL
		releaseURL.Path = path.Join(releaseURL.Path, release)
		files, err := u.traverse(releaseURL)
		if err != nil {
			return err
		}

		for _, file := range files {
			if err = u.Save(release, file); err != nil {
				return err
			}
		}
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

func (u Updater) Save(release, fileName string) error {
	log.Printf("  release: %s, file: %s", release, fileName)
	advisoryURL := *u.baseURL
	advisoryURL.Path = path.Join(advisoryURL.Path, release, fileName)
	b, err := utils.FetchURL(advisoryURL.String(), "", u.retry)
	if err != nil {
		return err
	}

	var secdb secdb
	if err = json.Unmarshal(b, &secdb); err != nil {
		return err
	}

	// "packages" might not be an array and it causes an unmarshal error.
	// See https://gitlab.alpinelinux.org/alpine/infra/docker/secdb/-/issues/2
	var v interface{}
	if err = json.Unmarshal(secdb.Packages, &v); err != nil {
		return err
	}
	if _, ok := v.([]interface{}); !ok {
		log.Printf("    skip release: %s, file: %s", release, fileName)
		return nil
	}

	// It should succeed now.
	var pkgs []packages
	if err = json.Unmarshal(secdb.Packages, &pkgs); err != nil {
		return err
	}

	for _, pkg := range pkgs {
		if err = u.savePkg(secdb, pkg.Pkg, release); err != nil {
			return err
		}
	}

	return nil
}

func (u Updater) savePkg(secdb secdb, pkg pkg, release string) error {
	secfixes := map[string][]string{}
	for fixedVersion, v := range pkg.Secfixes {
		// CVE-IDs might not be an array and it causes an unmarshal error.
		vv, ok := v.([]interface{})
		if !ok {
			log.Printf("    skip pkg: %s, version: %s", pkg.Name, fixedVersion)
			continue
		}
		var cveIDs []string
		for _, v := range vv {
			cveIDs = append(cveIDs, v.(string))
		}
		secfixes[fixedVersion] = cveIDs
	}
	advisory := advisory{
		Name:          pkg.Name,
		Secfixes:      secfixes,
		Apkurl:        secdb.Apkurl,
		Archs:         secdb.Archs,
		Urlprefix:     secdb.Urlprefix,
		Reponame:      secdb.Reponame,
		Distroversion: secdb.Distroversion,
	}

	release = strings.TrimPrefix(release, "v")
	dir := filepath.Join(u.vulnListDir, u.advisoryDir, release, secdb.Reponame)
	file := fmt.Sprintf("%s.json", pkg.Name)
	if err := utils.WriteJSON(u.appFs, dir, file, advisory); err != nil {
		return xerrors.Errorf("failed to write %s under %s: %w", file, dir, err)
	}

	return nil
}
