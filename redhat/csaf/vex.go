package csaf

import (
	"archive/tar"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/csaf-poc/csaf_distribution/v3/csaf"
	"github.com/klauspost/compress/zstd"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

// csvEntry represents a single entry from changes.csv or deletions.csv
type csvEntry struct {
	Path string // e.g., "2025/cve-2025-7195.json"
}

const (
	vexDir = "csaf-vex"
	// archiveKey tracks the archive the local data was last reconciled with.
	archiveKey = "csaf-vex-archive"
	retry      = 5
	baseURL    = "https://security.access.redhat.com/data/csaf/v2/vex/"
	timeBuffer = 6 * time.Hour // Buffer to handle delayed CSV updates
)

type Option func(*Config)

func WithBaseDir(dir string) Option {
	return func(c *Config) { c.baseDir = dir }
}

func WithBaseURL(url *url.URL) Option {
	return func(c *Config) { c.baseURL = url }
}

func WithRetry(retry int) Option {
	return func(c *Config) { c.retry = retry }
}

type Config struct {
	baseDir string
	baseURL *url.URL
	retry   int
}

func NewConfig(opts ...Option) *Config {
	c := Config{
		baseDir: filepath.Join(utils.VulnListDir(), vexDir),
		baseURL: lo.Must(url.Parse(baseURL)),
		retry:   retry,
	}
	for _, o := range opts {
		o(&c)
	}
	return &c
}

func (c *Config) Update() error {
	lastUpdated, err := utils.GetLastUpdatedDate(vexDir)
	if err != nil {
		return xerrors.Errorf("failed to get last updated date: %w", err)
	}

	reconciled, err := utils.GetLastUpdatedDate(archiveKey)
	if err != nil {
		return xerrors.Errorf("failed to get reconciled archive date: %w", err)
	}

	archiveName, archiveDate, err := c.latestArchive()
	if err != nil {
		return xerrors.Errorf("failed to get the latest archive: %w", err)
	}

	if archiveDate.After(reconciled) {
		if err = c.reconcileWithArchive(archiveName); err != nil {
			return xerrors.Errorf("failed to reconcile with archive %s: %w", archiveName, err)
		}
		if err = utils.SetLastUpdatedDate(archiveKey, archiveDate); err != nil {
			return xerrors.Errorf("failed to set reconciled archive date: %w", err)
		}
		// The archive is a snapshot taken on archiveDate, so anything published after it
		// has just been rolled back and the delta has to apply it again.
		lastUpdated = archiveDate
	}

	return c.updateFromDelta(lastUpdated)
}

// reconcileWithArchive brings the local data back in line with the archive, which is the
// only view Red Hat publishes of the current state. changes.csv and deletions.csv are event
// logs, and an entry can show up in them long after its own timestamp, so on its own the
// delta update drifts away from upstream and never comes back.
func (c *Config) reconcileWithArchive(archiveName string) error {
	log.Printf("Reconciling with %s...", archiveName)
	archivePath, err := c.fetchVEXArchive(archiveName)
	if err != nil {
		return xerrors.Errorf("failed to fetch VEX archive: %w", err)
	}
	defer os.Remove(archivePath)

	published, err := c.extractArchive(archivePath)
	if err != nil {
		return xerrors.Errorf("failed to extract archive: %w", err)
	}

	return c.removeUnpublished(published)
}

// removeUnpublished deletes local advisories that the archive no longer carries.
func (c *Config) removeUnpublished(published map[string]struct{}) error {
	var removed int
	err := filepath.Walk(c.baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(c.baseDir, path)
		if err != nil {
			return err
		}
		if _, ok := published[relPath]; ok {
			return nil
		}
		if err = os.Remove(path); err != nil {
			return err
		}
		removed++
		return nil
	})
	if err != nil {
		return xerrors.Errorf("failed to walk %s: %w", c.baseDir, err)
	}

	log.Printf("Removed %d advisories that are no longer published", removed)
	return nil
}

// extractArchive writes every advisory from the archive and returns their paths
// relative to the base directory.
func (c *Config) extractArchive(archivePath string) (map[string]struct{}, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, xerrors.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	d, err := zstd.NewReader(f)
	if err != nil {
		return nil, xerrors.Errorf("failed to create zstd reader: %w", err)
	}
	defer d.Close()

	published := make(map[string]struct{})
	tr := tar.NewReader(d)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, xerrors.Errorf("failed to read tar header: %w", err)
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		advisory, err := c.loadAdvisory(tr)
		if err != nil {
			return nil, xerrors.Errorf("failed to load advisory: %w", err)
		}

		fileName := filepath.Base(hdr.Name)
		cveID := strings.TrimSuffix(fileName, filepath.Ext(fileName))
		if err = utils.SaveCVEPerYear(c.baseDir, cveID, advisory); err != nil {
			return nil, xerrors.Errorf("failed to save advisory: %w", err)
		}

		// SaveCVEPerYear stores the advisory under the year taken from the CVE ID.
		published[filepath.Join(strings.Split(cveID, "-")[1], fileName)] = struct{}{}
	}

	return published, nil
}

// latestArchive returns the name of the archive Red Hat publishes as the latest one,
// together with the date it was built on.
func (c *Config) latestArchive() (string, time.Time, error) {
	u := c.baseURL.ResolveReference(&url.URL{Path: "archive_latest.txt"})
	log.Printf("Fetching the latest archive name from %s", u.String())
	b, err := utils.FetchURL(u.String(), "", c.retry)
	if err != nil {
		return "", time.Time{}, xerrors.Errorf("failed to fetch URL (%s): %w", u.String(), err)
	}
	archiveName := strings.TrimSpace(string(b))

	// Parse archive date from filename (e.g., "csaf_vex_2025-12-06.tar.zst")
	archiveDate, err := parseArchiveDate(archiveName)
	if err != nil {
		return "", time.Time{}, xerrors.Errorf("failed to parse archive date: %w", err)
	}

	return archiveName, archiveDate, nil
}

func (c *Config) fetchVEXArchive(archiveName string) (string, error) {
	u := c.baseURL.ResolveReference(&url.URL{Path: archiveName})
	log.Printf("  Fetching the archive from %s", u.String())
	b, err := utils.FetchURL(u.String(), "", c.retry)
	if err != nil {
		return "", xerrors.Errorf("failed to fetch URL (%s): %w", u.String(), err)
	}
	out, err := os.CreateTemp("", "csaf_vex_*.tar.zst")
	if err != nil {
		return "", xerrors.Errorf("failed to create temp file: %w", err)
	}
	defer out.Close()

	// Write the archive to a temp file
	if _, err = out.Write(b); err != nil {
		return "", xerrors.Errorf("failed to write to temp file: %w", err)
	}

	return out.Name(), nil
}

// loadAdvisory loads an advisory from a file and trims it down before it is saved.
func (c *Config) loadAdvisory(r io.Reader) (*csaf.Advisory, error) {
	var advisory csaf.Advisory
	if err := json.NewDecoder(r).Decode(&advisory); err != nil {
		return nil, xerrors.Errorf("json decode error: %w", err)
	}
	if err := advisory.Validate(); err != nil {
		return nil, xerrors.Errorf("invalid advisory: %w", err)
	}
	trimAdvisory(&advisory)
	return &advisory, nil
}

// trimAdvisory drops fields that nothing downstream reads, to keep the largest
// documents under GitHub's 100 MiB file limit.
// TODO: Remove this once the data can be stored losslessly.
func trimAdvisory(advisory *csaf.Advisory) {
	for _, vuln := range advisory.Vulnerabilities {
		if vuln == nil {
			continue
		}
		vuln.Scores = nil
		vuln.Flags = nil
		vuln.ProductStatus = nil
	}
}

func (c *Config) updateFromDelta(lastUpdated time.Time) error {
	// Use buffer to handle delayed CSV updates
	since := lastUpdated.Add(-timeBuffer)
	log.Printf("Performing delta update since %s (with %s buffer)", since.Format(time.RFC3339), timeBuffer)

	// Process changes
	if err := c.applyChanges(since); err != nil {
		return xerrors.Errorf("failed to apply changes: %w", err)
	}

	// Process deletions
	if err := c.applyDeletions(since); err != nil {
		return xerrors.Errorf("failed to apply deletions: %w", err)
	}

	// Update last updated to current time
	now := time.Now().UTC()
	if err := utils.SetLastUpdatedDate(vexDir, now); err != nil {
		return xerrors.Errorf("failed to set last updated date: %w", err)
	}
	log.Printf("Updated last updated date to %s", now.Format(time.RFC3339))

	return nil
}

func (c *Config) applyChanges(since time.Time) error {
	entries, err := c.fetchCSVEntries("changes.csv", since)
	if err != nil {
		return xerrors.Errorf("failed to fetch changes.csv: %w", err)
	}

	log.Printf("Found %d changed CVEs since %s", len(entries), since.Format(time.RFC3339))

	for _, entry := range entries {
		if err := c.fetchAndSaveCVE(entry.Path); err != nil {
			return xerrors.Errorf("failed to fetch CVE %s: %w", entry.Path, err)
		}
	}

	return nil
}

func (c *Config) applyDeletions(since time.Time) error {
	entries, err := c.fetchCSVEntries("deletions.csv", since)
	if err != nil {
		return xerrors.Errorf("failed to fetch deletions.csv: %w", err)
	}

	log.Printf("Found %d deleted CVEs since %s", len(entries), since.Format(time.RFC3339))

	for _, entry := range entries {
		// path is like "2025/cve-2025-22868.json"
		filePath := filepath.Join(c.baseDir, entry.Path)

		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			return xerrors.Errorf("failed to remove %s: %w", filePath, err)
		}
	}

	return nil
}

func (c *Config) fetchCSVEntries(filename string, since time.Time) ([]csvEntry, error) {
	u := c.baseURL.ResolveReference(&url.URL{Path: filename})
	log.Printf("Fetching %s from %s", filename, u.String())

	b, err := utils.FetchURL(u.String(), "", c.retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch %s: %w", filename, err)
	}

	return parseCSV(b, since)
}

func (c *Config) fetchAndSaveCVE(path string) error {
	// path is like "2025/cve-2025-7195.json"
	u := c.baseURL.ResolveReference(&url.URL{Path: path})

	b, err := utils.FetchURL(u.String(), "", c.retry)
	if err != nil {
		return xerrors.Errorf("failed to fetch CVE: %w", err)
	}

	advisory, err := c.loadAdvisory(bytes.NewReader(b))
	if err != nil {
		return xerrors.Errorf("failed to load advisory: %w", err)
	}

	// Extract CVE ID from path (e.g., "2025/cve-2025-7195.json" -> "cve-2025-7195")
	fileName := filepath.Base(path)
	cveID := strings.TrimSuffix(fileName, filepath.Ext(fileName))

	if err = utils.SaveCVEPerYear(c.baseDir, cveID, advisory); err != nil {
		return xerrors.Errorf("failed to save advisory: %w", err)
	}

	return nil
}

// archiveDateRegex matches archive filenames like "csaf_vex_2025-12-06.tar.zst"
var archiveDateRegex = regexp.MustCompile(`csaf_vex_(\d{4}-\d{2}-\d{2})\.tar\.zst`)

// parseArchiveDate extracts the date from an archive filename.
// e.g., "csaf_vex_2025-12-06.tar.zst" -> 2025-12-06T00:00:00Z
func parseArchiveDate(archiveName string) (time.Time, error) {
	matches := archiveDateRegex.FindStringSubmatch(archiveName)
	if len(matches) != 2 {
		return time.Time{}, xerrors.Errorf("failed to parse archive date from %q", archiveName)
	}
	t, err := time.Parse("2006-01-02", matches[1])
	if err != nil {
		return time.Time{}, xerrors.Errorf("failed to parse date %q: %w", matches[1], err)
	}
	return t.UTC(), nil
}

// parseCSV reads CSV entries until it finds an entry older than `since`.
// CSV is sorted newest-first, so we can stop early.
func parseCSV(b []byte, since time.Time) ([]csvEntry, error) {
	csvReader := csv.NewReader(bytes.NewReader(b))
	var entries []csvEntry

	for {
		record, err := csvReader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, xerrors.Errorf("failed to read CSV record: %w", err)
		}

		if len(record) != 2 {
			return nil, xerrors.Errorf("invalid CSV record: expected 2 fields, got %d", len(record))
		}

		updatedAt, err := time.Parse(time.RFC3339, record[1])
		if err != nil {
			return nil, xerrors.Errorf("failed to parse timestamp %q: %w", record[1], err)
		}

		// CSV is sorted newest-first, stop when we reach old entries
		if !updatedAt.After(since) {
			break
		}

		entries = append(entries, csvEntry{
			Path: record[0],
		})
	}
	return entries, nil
}
