package seal

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/osv"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	// renamedFeedURL contains advisories for packages that Seal renames
	// (e.g. "seal-requests", "@seal-security/ajv").
	renamedFeedURL = "https://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip"
	// originalFeedURL contains advisories for packages that keep their original
	// name and only change the version (e.g. "requests" at "2.14.2+sp1").
	originalFeedURL = "https://vulnfeed.sealsecurity.io/v1/osv/vulnerabilities.zip"
	sealDir         = "seal"
)

// Trivy reads Seal advisories from a single "seal" directory, so both feeds
// must be combined there rather than published separately.
var defaultFeedURLs = []string{originalFeedURL, renamedFeedURL}

type options struct {
	dir      string
	feedURLs []string
}

type Option func(*options)

func WithDir(dir string) Option {
	return func(opts *options) {
		opts.dir = dir
	}
}

func WithFeedURLs(feedURLs []string) Option {
	return func(opts *options) {
		opts.feedURLs = feedURLs
	}
}

// Updater downloads Seal's OSV feeds and stores them in the vuln-list "seal"
// directory.
type Updater struct {
	dir      string
	feedURLs []string
}

func NewSeal(opts ...Option) Updater {
	o := &options{
		dir:      utils.VulnListDir(),
		feedURLs: defaultFeedURLs,
	}

	for _, opt := range opts {
		opt(o)
	}

	return Updater{
		dir:      o.dir,
		feedURLs: o.feedURLs,
	}
}

// Update merges every Seal feed into the "seal" directory.
//
// Each feed only carries its own advisories, so the directory is cleared a
// single time before any feed is fetched: clearing it per feed would let a
// later feed delete the advisories an earlier one just wrote, and skipping it
// would leave behind advisories that have since been withdrawn from the source.
func (u Updater) Update() error {
	ctx := context.Background()

	sealPath := filepath.Join(u.dir, sealDir)
	log.Printf("[Seal] Removing %s directory", sealPath)
	if err := os.RemoveAll(sealPath); err != nil {
		return xerrors.Errorf("failed to remove %s directory: %w", sealPath, err)
	}

	for _, feedURL := range u.feedURLs {
		log.Printf("Updating Seal advisories from %s", feedURL)
		if err := u.updateFromFeed(ctx, sealPath, feedURL); err != nil {
			return err
		}
	}
	return nil
}

// updateFromFeed adds one feed's advisories to sealPath without clearing what
// is already there, so feeds accumulate rather than replace one another.
func (u Updater) updateFromFeed(ctx context.Context, sealPath, feedURL string) error {
	tempDir, err := utils.DownloadToTempDir(ctx, feedURL)
	if err != nil {
		return xerrors.Errorf("failed to download %s: %w", feedURL, err)
	}

	err = filepath.WalkDir(tempDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		} else if d.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return xerrors.Errorf("file open error (%s): %w", path, err)
		}

		var parsed osv.OSV
		if err = json.NewDecoder(f).Decode(&parsed); err != nil {
			return xerrors.Errorf("unable to parse json %s: %w", path, err)
		}

		if len(parsed.Affected) == 0 {
			log.Printf("[Seal] skipping %s: no affected packages", parsed.ID)
			return nil
		}

		// Maven package names are "groupId:artifactId"; the colon is not safe in a
		// path, so it becomes a directory separator.
		pkgName := strings.ReplaceAll(parsed.Affected[0].Package.Name, ":", "/")
		filePath := filepath.Join(sealPath, pkgName, fmt.Sprintf("%s.json", parsed.ID))
		if err = utils.Write(filePath, parsed); err != nil {
			return xerrors.Errorf("failed to write file: %w", err)
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}
	return nil
}
