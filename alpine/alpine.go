package alpine

import (
	"bytes"
	"encoding/json"
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
	u, _ := url.Parse(repoURL)
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
	dir := filepath.Join(u.vulnListDir, alpineDir)
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
		if !strings.HasPrefix(selection.Text(), "v") {
			return
		}
		releases = append(releases, selection.Text())
	})

	for _, release := range releases {
		releaseURL := *u.baseURL
		releaseURL.Path = path.Join(releaseURL.Path, release)
		files, err := u.traverse(releaseURL)
		if err != nil {
			return err
		}

		for _, file := range files {
			if err = u.save(release, file); err != nil {
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

func (u Updater) save(release, fileName string) error {
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

	// Packages might not be an array and it causes an unmarshal error.
	if _, ok := secdb.Packages.([]interface{}); !ok {
		secdb.Packages = nil
	}

	release = strings.TrimPrefix(release, "v")
	dir := filepath.Join(u.vulnListDir, alpineDir, release)
	if err := utils.WriteJSON(u.appFs, dir, fileName, secdb); err != nil {
		return xerrors.Errorf("failed to write %s under %s: %w", fileName, dir, err)
	}
	return nil
}
