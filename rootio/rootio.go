package rootio

import (
	"encoding/json"
	"log"
	"net/url"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	rootioDir      = "rootio"
	cveFeedURLBase = "https://api.root.io"
	cveFeedPath    = "external/cve_feed"
	retry          = 3
)

type option func(c *Updater)

func WithVulnListDir(v string) option {
	return func(c *Updater) { c.vulnListDir = v }
}

func WithBaseURL(v *url.URL) option {
	return func(c *Updater) { c.baseURL = v }
}

func WithRetry(r int) option {
	return func(c *Updater) { c.retry = r }
}

type Updater struct {
	vulnListDir string
	baseURL     *url.URL
	retry       int
}

func NewUpdater(options ...option) *Updater {
	u, _ := url.Parse(cveFeedURLBase)
	updater := &Updater{
		vulnListDir: utils.VulnListDir(),
		baseURL:     u,
		retry:       retry,
	}
	for _, option := range options {
		option(updater)
	}

	return updater
}

func (u *Updater) Update() error {
	dir := filepath.Join(u.vulnListDir, rootioDir)
	log.Printf("Remove Root.io directory %s", dir)
	if err := os.RemoveAll(dir); err != nil {
		return xerrors.Errorf("failed to remove Root.io directory: %w", err)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return xerrors.Errorf("Root.io mkdir error: %w", err)
	}

	log.Println("Fetching Root.io CVE data...")

	feedURL := u.baseURL.JoinPath(cveFeedPath)
	data, err := utils.FetchURL(feedURL.String(), "", u.retry)
	if err != nil {
		return xerrors.Errorf("Failed to fetch Root.io CVE feed from %s: %w", feedURL.String(), err)
	}

	var cveFeed CVEFeed
	if err := json.Unmarshal(data, &cveFeed); err != nil {
		return xerrors.Errorf("failed to parse Root.io CVE feed JSON: %w", err)
	}

	// Save the entire feed as a single JSON file
	feedFilePath := filepath.Join(dir, "cve_feed.json")
	if err := write(feedFilePath, cveFeed); err != nil {
		return xerrors.Errorf("failed to write Root.io CVE feed to %s: %w", feedFilePath, err)
	}

	log.Printf("Root.io CVE data updated successfully in %s", feedFilePath)
	return nil
}

// write writes data to filePath using json.Marshal (without formatting)
// This is a local version of utils.Write that doesn't format the JSON,
// which is needed to keep the root.io feed file small enough for GitHub.
func write(filePath string, data interface{}) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to create %s: %w", dir, err)
	}

	f, err := os.Create(filePath)
	if err != nil {
		return xerrors.Errorf("file create error: %w", err)
	}
	defer f.Close()

	b, err := json.Marshal(data)
	if err != nil {
		return xerrors.Errorf("JSON marshal error: %w", err)
	}

	_, err = f.Write(b)
	if err != nil {
		return xerrors.Errorf("file write error: %w", err)
	}
	return nil
}
