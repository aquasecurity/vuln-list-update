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
	retry          = 3

	feedFileName = "cve_feed.json"
)

// feeds defines the feeds to fetch
// API path -> subdirectory
var feeds = map[string]string{
	"external/cve_feed": "",    // OS packages feed (legacy endpoint)
	"external/app_feed": "app", // Application packages feed
}

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
	for _, o := range options {
		o(updater)
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

	// Fetch and save feeds
	for apiPath, subDir := range feeds {
		if err := u.fetchAndSaveFeed(apiPath, subDir); err != nil {
			return err
		}
	}

	return nil
}

// fetchAndSaveFeed fetches a feed from the given path and saves it to the specified file
func (u *Updater) fetchAndSaveFeed(apiPath, subdir string) error {
	feedURL := u.baseURL.JoinPath(apiPath)
	log.Printf("Fetching Root.io data from %s...", feedURL.String())

	data, err := utils.FetchURL(feedURL.String(), "", u.retry)
	if err != nil {
		return xerrors.Errorf("Failed to fetch Root.io feed from %s: %w", feedURL.String(), err)
	}

	var feedData CVEFeed
	if err = json.Unmarshal(data, &feedData); err != nil {
		return xerrors.Errorf("failed to parse Root.io feed JSON: %w", err)
	}

	// Determine the target directory
	targetDir := filepath.Join(u.vulnListDir, rootioDir, subdir)
	if err = os.MkdirAll(targetDir, 0755); err != nil {
		return xerrors.Errorf("failed to create directory %s: %w", targetDir, err)
	}

	// Save feed
	feedFilePath := filepath.Join(targetDir, feedFileName)
	if err = utils.Write(feedFilePath, feedData); err != nil {
		return xerrors.Errorf("failed to write Root.io feed to %s: %w", feedFilePath, err)
	}
	log.Printf("Root.io data updated successfully in %s", feedFilePath)

	return nil
}
