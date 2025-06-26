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
)

type option func(c *Updater)

func WithVulnListDir(v string) option {
	return func(c *Updater) { c.vulnListDir = v }
}

func WithBaseURL(v *url.URL) option {
	return func(c *Updater) { c.baseURL = v }
}

type Updater struct {
	vulnListDir string
	baseURL     *url.URL
}

func NewUpdater(options ...option) *Updater {
	u, _ := url.Parse(cveFeedURLBase)
	updater := &Updater{
		vulnListDir: utils.VulnListDir(),
		baseURL:     u,
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

	feedUrl := u.baseURL.JoinPath(cveFeedPath)
	data, err := utils.FetchURL(feedUrl.String(), "", 2)
	if err != nil {
		return xerrors.Errorf("Failed to fetch Root.io CVE feed from %s: %w", feedUrl.String(), err)
	}

	var cveFeed CVEFeed
	if err := json.Unmarshal(data, &cveFeed); err != nil {
		return xerrors.Errorf("failed to parse Root.io CVE feed JSON: %w", err)
	}

	// Save the entire feed as a single JSON file
	feedFilePath := filepath.Join(dir, "cve_feed.json")
	if err := utils.Write(feedFilePath, cveFeed); err != nil {
		return xerrors.Errorf("failed to write Root.io CVE feed to %s: %w", feedFilePath, err)
	}

	log.Printf("Root.io CVE data updated successfully in %s", feedFilePath)
	return nil
}
