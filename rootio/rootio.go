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
)

// feedInfo contains the information for each feed type
type feedInfo struct {
	path     string // API path
	subDir   string // subdirectory under rootio
	fileName string // output filename
}

// feeds defines the feeds to fetch
var feeds = []feedInfo{
	{path: "external/cve_feed", subDir: "", fileName: "cve_feed.json"},    // OS packages feed (legacy endpoint)
	{path: "external/app_feed", subDir: "app", fileName: "cve_feed.json"}, // Application packages feed
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

	// Fetch and save feeds
	for _, feed := range feeds {
		if err := u.fetchAndSaveFeed(feed); err != nil {
			return err
		}
	}

	return nil
}

// fetchAndSaveFeed fetches a feed from the given path and saves it to the specified file
func (u *Updater) fetchAndSaveFeed(feed feedInfo) error {
	feedURL := u.baseURL.JoinPath(feed.path)
	log.Printf("Fetching Root.io data from %s...", feedURL.String())

	data, err := utils.FetchURL(feedURL.String(), "", u.retry)
	if err != nil {
		return xerrors.Errorf("Failed to fetch Root.io feed from %s: %w", feedURL.String(), err)
	}

	var feedData CVEFeed
	if err := json.Unmarshal(data, &feedData); err != nil {
		return xerrors.Errorf("failed to parse Root.io feed JSON: %w", err)
	}

	// Determine the target directory
	var targetDir string
	if feed.subDir != "" {
		targetDir = filepath.Join(u.vulnListDir, rootioDir, feed.subDir)
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			return xerrors.Errorf("failed to create directory %s: %w", targetDir, err)
		}
	} else {
		targetDir = filepath.Join(u.vulnListDir, rootioDir)
	}

	// Save feed
	feedFilePath := filepath.Join(targetDir, feed.fileName)
	if err := utils.Write(feedFilePath, feedData); err != nil {
		return xerrors.Errorf("failed to write Root.io feed to %s: %w", feedFilePath, err)
	}
	log.Printf("Root.io data updated successfully in %s", feedFilePath)

	return nil
}
