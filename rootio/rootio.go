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
	osFeedPath     = "external/os_feed"  // OS packages feed
	appFeedPath    = "external/app_feed" // Language/app packages feed
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

	// Fetch and save OS feed
	if err := u.fetchAndSaveFeed(osFeedPath, "os_feed.json", "OS package"); err != nil {
		return err
	}

	// Fetch and save app feed
	if err := u.fetchAndSaveFeed(appFeedPath, "app_feed.json", "application package"); err != nil {
		return err
	}

	return nil
}

// fetchAndSaveFeed fetches a feed from the given path and saves it to the specified file
func (u *Updater) fetchAndSaveFeed(feedPath, fileName, feedType string) error {
	log.Printf("Fetching Root.io %s data...", feedType)
	feedURL := u.baseURL.JoinPath(feedPath)
	data, err := utils.FetchURL(feedURL.String(), "", u.retry)
	if err != nil {
		return xerrors.Errorf("Failed to fetch Root.io %s feed from %s: %w", feedType, feedURL.String(), err)
	}

	var feed CVEFeed
	if err := json.Unmarshal(data, &feed); err != nil {
		return xerrors.Errorf("failed to parse Root.io %s feed JSON: %w", feedType, err)
	}

	// Save feed
	feedFilePath := filepath.Join(u.vulnListDir, rootioDir, fileName)
	if err := utils.Write(feedFilePath, feed); err != nil {
		return xerrors.Errorf("failed to write Root.io %s feed to %s: %w", feedType, feedFilePath, err)
	}
	log.Printf("Root.io %s data updated successfully in %s", feedType, feedFilePath)

	return nil
}
