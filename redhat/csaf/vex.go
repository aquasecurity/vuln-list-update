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
	Path      string    // e.g., "2025/cve-2025-7195.json"
	UpdatedAt time.Time // e.g., 2025-12-12T10:07:18+00:00
}

const (
	vexDir  = "csaf-vex"
	retry   = 5
	baseURL = "https://security.access.redhat.com/data/csaf/v2/vex/"
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

	if lastUpdated.Unix() == 0 {
		// Not updated yet
		exists, err := utils.Exists(c.baseDir)
		if err != nil {
			return xerrors.Errorf("failed to check base dir: %w", err)
		}

		if exists {
			// vuln-list-redhat is cloned externally, just set archive date
			archiveDate, err := c.fetchArchiveDate()
			if err != nil {
				return xerrors.Errorf("failed to fetch archive date: %w", err)
			}
			if err := utils.SetLastUpdatedDate(vexDir, archiveDate); err != nil {
				return xerrors.Errorf("failed to set last updated date: %w", err)
			}
			log.Printf("Set last updated date to archive date: %s", archiveDate.Format(time.RFC3339))
		} else {
			// First run - download and extract archive
			if err := c.updateFromArchive(); err != nil {
				return xerrors.Errorf("archive update failed: %w", err)
			}
		}
	}

	return c.updateFromDelta()
}

func (c *Config) fetchArchiveDate() (time.Time, error) {
	u := c.baseURL.ResolveReference(&url.URL{Path: "archive_latest.txt"})
	log.Printf("  Fetching the latest archive name from %s", u.String())
	b, err := utils.FetchURL(u.String(), "", c.retry)
	if err != nil {
		return time.Time{}, xerrors.Errorf("failed to fetch URL (%s): %w", u.String(), err)
	}
	archiveName := strings.TrimSpace(string(b))

	archiveDate, err := parseArchiveDate(archiveName)
	if err != nil {
		return time.Time{}, xerrors.Errorf("failed to parse archive date: %w", err)
	}

	return archiveDate, nil
}

func (c *Config) updateFromArchive() error {
	log.Println("Fetching Red Hat CSAF VEX archive...")
	archivePath, archiveDate, err := c.fetchVEXArchive()
	if err != nil {
		return xerrors.Errorf("failed to fetch VEX archive: %w", err)
	}
	defer os.Remove(archivePath)

	// Set last updated to archive date before extraction
	if err := utils.SetLastUpdatedDate(vexDir, archiveDate); err != nil {
		return xerrors.Errorf("failed to set last updated date: %w", err)
	}
	log.Printf("Set last updated date to archive date: %s", archiveDate.Format(time.RFC3339))

	if err := c.extractArchive(archivePath); err != nil {
		return xerrors.Errorf("failed to extract archive: %w", err)
	}

	return nil
}

func (c *Config) extractArchive(archivePath string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return xerrors.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	d, err := zstd.NewReader(f)
	if err != nil {
		return xerrors.Errorf("failed to create zstd reader: %w", err)
	}
	defer d.Close()

	tr := tar.NewReader(d)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return xerrors.Errorf("failed to read tar header: %w", err)
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		advisory, err := c.loadAdvisory(tr)
		if err != nil {
			return xerrors.Errorf("failed to load advisory: %w", err)
		}

		fileName := filepath.Base(hdr.Name)
		cveID := strings.TrimSuffix(fileName, filepath.Ext(fileName))
		if err = utils.SaveCVEPerYear(c.baseDir, cveID, advisory); err != nil {
			return xerrors.Errorf("failed to save advisory: %w", err)
		}
	}

	return nil
}

func (c *Config) fetchVEXArchive() (string, time.Time, error) {
	// Fetch the latest archive name
	u := c.baseURL.ResolveReference(&url.URL{Path: "archive_latest.txt"})
	log.Printf("  Fetching the latest archive name from %s", u.String())
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

	// Fetch the latest archive
	u = c.baseURL.ResolveReference(&url.URL{Path: archiveName})
	log.Printf("  Fetching the latest archive from %s", u.String())
	b, err = utils.FetchURL(u.String(), "", c.retry)
	if err != nil {
		return "", time.Time{}, xerrors.Errorf("failed to fetch URL (%s): %w", u.String(), err)
	}
	out, err := os.CreateTemp("", "csaf_vex_*.tar.zst")
	if err != nil {
		return "", time.Time{}, xerrors.Errorf("failed to create temp file: %w", err)
	}
	defer out.Close()

	// Write the archive to a temp file
	if _, err = out.Write(b); err != nil {
		return "", time.Time{}, xerrors.Errorf("failed to write to temp file: %w", err)
	}

	return out.Name(), archiveDate, nil
}

// loadAdvisory loads an advisory from a file.
func (c *Config) loadAdvisory(r io.Reader) (*csaf.Advisory, error) {
	var advisory csaf.Advisory
	if err := json.NewDecoder(r).Decode(&advisory); err != nil {
		return nil, xerrors.Errorf("json decode error: %w", err)
	}
	if err := advisory.Validate(); err != nil {
		return nil, xerrors.Errorf("invalid advisory: %w", err)
	}
	return &advisory, nil
}

func (c *Config) updateFromDelta() error {
	lastUpdated, err := utils.GetLastUpdatedDate(vexDir)
	if err != nil {
		return xerrors.Errorf("failed to get last updated date: %w", err)
	}

	log.Printf("Performing delta update since %s", lastUpdated.Format(time.RFC3339))

	var maxTime time.Time

	// Process changes
	changesMaxTime, err := c.applyChanges(lastUpdated)
	if err != nil {
		return xerrors.Errorf("failed to apply changes: %w", err)
	}
	if changesMaxTime.After(maxTime) {
		maxTime = changesMaxTime
	}

	// Process deletions
	deletionsMaxTime, err := c.applyDeletions(lastUpdated)
	if err != nil {
		return xerrors.Errorf("failed to apply deletions: %w", err)
	}
	if deletionsMaxTime.After(maxTime) {
		maxTime = deletionsMaxTime
	}

	// Update last updated to max processed time (not now)
	if !maxTime.IsZero() {
		if err := utils.SetLastUpdatedDate(vexDir, maxTime); err != nil {
			return xerrors.Errorf("failed to set last updated date: %w", err)
		}
		log.Printf("Updated last updated date to %s", maxTime.Format(time.RFC3339))
	}

	return nil
}

func (c *Config) applyChanges(since time.Time) (time.Time, error) {
	entries, err := c.fetchCSVEntries("changes.csv", since)
	if err != nil {
		return time.Time{}, xerrors.Errorf("failed to fetch changes.csv: %w", err)
	}

	log.Printf("Found %d changed CVEs since %s", len(entries), since.Format(time.RFC3339))

	var maxTime time.Time
	for _, entry := range entries {
		if err := c.fetchAndSaveCVE(entry.Path); err != nil {
			return time.Time{}, xerrors.Errorf("failed to fetch CVE %s: %w", entry.Path, err)
		}
		if entry.UpdatedAt.After(maxTime) {
			maxTime = entry.UpdatedAt
		}
	}

	return maxTime, nil
}

func (c *Config) applyDeletions(since time.Time) (time.Time, error) {
	entries, err := c.fetchCSVEntries("deletions.csv", since)
	if err != nil {
		return time.Time{}, xerrors.Errorf("failed to fetch deletions.csv: %w", err)
	}

	log.Printf("Found %d deleted CVEs since %s", len(entries), since.Format(time.RFC3339))

	var maxTime time.Time
	for _, entry := range entries {
		// path is like "2025/cve-2025-22868.json"
		filePath := filepath.Join(c.baseDir, entry.Path)

		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			return time.Time{}, xerrors.Errorf("failed to remove %s: %w", filePath, err)
		}
		if entry.UpdatedAt.After(maxTime) {
			maxTime = entry.UpdatedAt
		}
	}

	return maxTime, nil
}

func (c *Config) fetchCSVEntries(filename string, since time.Time) ([]csvEntry, error) {
	u := c.baseURL.ResolveReference(&url.URL{Path: filename})
	log.Printf("Fetching %s from %s", filename, u.String())

	b, err := utils.FetchURL(u.String(), "", c.retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch %s: %w", filename, err)
	}

	return parseCSVStream(bytes.NewReader(b), since)
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

// parseCSVStream reads CSV entries until it finds an entry older than `since`.
// CSV is sorted newest-first, so we can stop early.
func parseCSVStream(r io.Reader, since time.Time) ([]csvEntry, error) {
	csvReader := csv.NewReader(r)
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
			Path:      record[0],
			UpdatedAt: updatedAt,
		})
	}
	return entries, nil
}
