package csaf

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/csaf-poc/csaf_distribution/v3/csaf"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

// csvEntry represents a single entry from changes.csv or deletions.csv
type csvEntry struct {
	Path string // e.g., "2025/cve-2025-7195.json"
}

const (
	vexDir       = "csaf-vex"
	cpeDir       = "csaf-vex-cpe"
	retry        = 5
	baseURL      = "https://security.access.redhat.com/data/csaf/v2/vex-feed/"
	repoToCPEURL = "https://security.access.redhat.com/data/metrics/repository-to-cpe.json"
	timeBuffer   = 6 * time.Hour // Buffer to handle delayed CSV updates
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

func WithNow(now func() time.Time) Option {
	return func(c *Config) { c.now = now }
}

type Config struct {
	baseDir string
	baseURL *url.URL
	retry   int
	now     func() time.Time
}

func NewConfig(opts ...Option) *Config {
	c := Config{
		baseDir: filepath.Join(utils.VulnListDir(), vexDir),
		baseURL: lo.Must(url.Parse(baseURL)),
		retry:   retry,
		now:     time.Now,
	}
	for _, o := range opts {
		o(&c)
	}
	return &c
}

func (c *Config) Update() error {
	if err := c.fetchCPEMapping(); err != nil {
		return xerrors.Errorf("failed to fetch CPE mapping: %w", err)
	}

	lastUpdated, err := utils.GetLastUpdatedDate(vexDir)
	if err != nil {
		return xerrors.Errorf("failed to get last updated date: %w", err)
	}

	if lastUpdated.Unix() == 0 {
		// Not updated yet - delete any stale data and download fresh archive
		if err := os.RemoveAll(c.baseDir); err != nil {
			return xerrors.Errorf("failed to remove base dir: %w", err)
		}
		lastUpdated, err = c.updateFromArchive()
		if err != nil {
			return xerrors.Errorf("archive update failed: %w", err)
		}
	}

	return c.updateFromDelta(lastUpdated)
}

// fetchCPEMapping downloads the public repository-to-cpe.json and saves it
// in the format the trivy-db parser expects.
func (c *Config) fetchCPEMapping() error {
	log.Println("Fetching repository-to-CPE mapping...")
	b, err := utils.FetchURL(repoToCPEURL, "", c.retry)
	if err != nil {
		return xerrors.Errorf("failed to fetch repository-to-cpe.json: %w", err)
	}

	var raw struct {
		Data map[string]struct {
			CPEs []string `json:"cpes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return xerrors.Errorf("failed to parse repository-to-cpe.json: %w", err)
	}

	repoToCPE := make(map[string][]string)
	for repo, entry := range raw.Data {
		repoToCPE[repo] = entry.CPEs
	}

	cpeDirPath := filepath.Join(utils.VulnListDir(), cpeDir)
	if err := os.MkdirAll(cpeDirPath, 0755); err != nil {
		return xerrors.Errorf("failed to create CPE directory: %w", err)
	}

	if err := utils.Write(filepath.Join(cpeDirPath, "repository-to-cpe.json"), repoToCPE); err != nil {
		return xerrors.Errorf("failed to write repository-to-cpe.json: %w", err)
	}

	// Write an empty nvr-to-cpe.json since the parser expects it
	if err := utils.Write(filepath.Join(cpeDirPath, "nvr-to-cpe.json"), map[string][]string{}); err != nil {
		return xerrors.Errorf("failed to write nvr-to-cpe.json: %w", err)
	}

	log.Printf("Saved %d repo-to-CPE mappings", len(repoToCPE))
	return nil
}

func (c *Config) updateFromArchive() (time.Time, error) {
	log.Println("Fetching Red Hat CSAF VEX archive...")
	archivePath, archiveDate, err := c.fetchVEXArchive()
	if err != nil {
		return time.Time{}, xerrors.Errorf("failed to fetch VEX archive: %w", err)
	}
	defer os.Remove(archivePath)

	if err := c.extractArchive(archivePath); err != nil {
		return time.Time{}, xerrors.Errorf("failed to extract archive: %w", err)
	}

	log.Printf("Archive date: %s", archiveDate.Format(time.RFC3339))
	return archiveDate, nil
}

func (c *Config) extractArchive(archivePath string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return xerrors.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return xerrors.Errorf("failed to create gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
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

	// Get the archive's Last-Modified date via HEAD request so the delta
	// window covers everything since the archive was actually created,
	// not since we downloaded it.
	archiveURL := c.baseURL.ResolveReference(&url.URL{Path: archiveName})
	archiveDate, err := c.fetchLastModified(archiveURL.String())
	if err != nil {
		log.Printf("  Warning: could not get Last-Modified, using current time: %v", err)
		archiveDate = c.now().UTC()
	}

	// Fetch the latest archive
	log.Printf("  Fetching the latest archive from %s", archiveURL.String())
	b, err = utils.FetchURL(archiveURL.String(), "", c.retry)
	if err != nil {
		return "", time.Time{}, xerrors.Errorf("failed to fetch URL (%s): %w", archiveURL.String(), err)
	}
	out, err := os.CreateTemp("", "csaf_vex_*.tar.gz")
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

// fetchLastModified returns the Last-Modified date of a URL via a HEAD request.
func (c *Config) fetchLastModified(url string) (time.Time, error) {
	resp, err := http.Head(url)
	if err != nil {
		return time.Time{}, xerrors.Errorf("HEAD request failed: %w", err)
	}
	defer resp.Body.Close()

	lm := resp.Header.Get("Last-Modified")
	if lm == "" {
		return time.Time{}, xerrors.New("no Last-Modified header")
	}

	t, err := http.ParseTime(lm)
	if err != nil {
		return time.Time{}, xerrors.Errorf("failed to parse Last-Modified %q: %w", lm, err)
	}
	return t.UTC(), nil
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
	ts := c.now().UTC()
	if err := utils.SetLastUpdatedDate(vexDir, ts); err != nil {
		return xerrors.Errorf("failed to set last updated date: %w", err)
	}
	log.Printf("Updated last updated date to %s", ts.Format(time.RFC3339))

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

// parseTimestamp parses a timestamp string, trying RFC3339 first
// then falling back to the "+0000" variant without the colon in the offset.
func parseTimestamp(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		return t, nil
	}
	t, err2 := time.Parse("2006-01-02T15:04:05-0700", s)
	if err2 == nil {
		return t, nil
	}
	return time.Time{}, err
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

		updatedAt, err := parseTimestamp(record[1])
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
