package csaf

import (
	"archive/tar"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gocsaf/csaf/v3/csaf"
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
	vexDir     = "csaf-vex"
	retry      = 5
	baseURL    = "https://security.access.redhat.com/data/csaf/v2/vex/"
	timeBuffer = 6 * time.Hour // Buffer to handle delayed CSV updates

	// maxFileSize keeps a saved file under GitHub's 100 MiB per-file limit, with headroom.
	// A document whose indented JSON exceeds it is split into several files instead.
	maxFileSize = 95 << 20
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

func WithMaxFileSize(size int) Option {
	return func(c *Config) { c.maxFileSize = size }
}

type Config struct {
	baseDir     string
	baseURL     *url.URL
	retry       int
	maxFileSize int
}

func NewConfig(opts ...Option) *Config {
	c := Config{
		baseDir:     filepath.Join(utils.VulnListDir(), vexDir),
		baseURL:     lo.Must(url.Parse(baseURL)),
		retry:       retry,
		maxFileSize: maxFileSize,
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
		if err = c.saveAdvisory(cveID, advisory); err != nil {
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

// loadAdvisory loads and validates an advisory.
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

// saveAdvisory writes an advisory to <year>/<cve-id>.json, indented.
// A document whose indented JSON exceeds maxFileSize is split into the <year>/<cve-id>/ directory instead (see splitAdvisory), so it is stored losslessly under GitHub's per-file limit.
// Only one of the two representations exists per CVE: writing one removes the other.
// If the document cannot be split into files that fit in maxFileSize, an error is returned and the files on disk are left untouched.
func (c *Config) saveAdvisory(cveID string, advisory *csaf.Advisory) error {
	matches := cveIDRegex.FindStringSubmatch(cveID)
	if matches == nil {
		return xerrors.Errorf("invalid CVE-ID format: %s", cveID)
	}
	yearDir := filepath.Join(c.baseDir, matches[1])
	filePath := filepath.Join(yearDir, cveID+".json")
	splitDir := filepath.Join(yearDir, cveID)

	b, err := json.MarshalIndent(advisory, "", "  ")
	if err != nil {
		return xerrors.Errorf("json marshal error: %w", err)
	}

	// All files are built before anything on disk is changed, so a document that cannot be split leaves the files on disk untouched.
	files := []splitFile{{path: filePath, data: b}}
	if len(b) > c.maxFileSize {
		parts, err := c.splitAdvisory(advisory)
		if err != nil {
			return xerrors.Errorf("failed to split %s (%d bytes, over the %d byte limit): %w", cveID, len(b), c.maxFileSize, err)
		}
		log.Printf("  %s is %d bytes, over the %d byte limit: splitting it into %d files", cveID, len(b), c.maxFileSize, len(parts))
		files = lo.Map(parts, func(f splitFile, _ int) splitFile {
			return splitFile{path: filepath.Join(splitDir, f.path), data: f.data}
		})
	}

	// Both representations are removed first: a document can move between them in either direction, and the split directory may hold parts of an earlier, larger split.
	if err = removeIfExists(filePath); err != nil {
		return err
	}
	if err = os.RemoveAll(splitDir); err != nil {
		return xerrors.Errorf("failed to remove %s: %w", splitDir, err)
	}

	for _, f := range files {
		dir := filepath.Dir(f.path)
		if err = os.MkdirAll(dir, os.ModePerm); err != nil {
			return xerrors.Errorf("failed to create %s: %w", dir, err)
		}
		if err = os.WriteFile(f.path, f.data, 0o644); err != nil {
			return xerrors.Errorf("file write error: %w", err)
		}
	}
	return nil
}

// splitFile is a file to write.
// splitAdvisory returns paths relative to the split directory.
type splitFile struct {
	path string
	data []byte
}

// splitAdvisory splits an advisory into files that each fit in maxFileSize:
//   - document.json holds the advisory without product_tree.branches, product_tree.relationships and the product arrays of the vulnerabilities;
//   - branches-NNNN.json hold product_tree.branches, split by splitArray and splitBranch;
//   - relationships-NNNN.json hold product_tree.relationships, split by splitArray;
//   - vulnerabilities-NNNN-<field>-NNNN.json hold the product arrays of each vulnerability, numbered from 1 (see splitVulnerability).
//
// These arrays list products, so they grow with the number of products, while the rest of the document stays small.
// Reading the files back means concatenating the arrays from the numbered files of each array in order, recursively merging adjacent branches with the same category and name, merging adjacent scores, threats, flags and remediations that differ only in their product lists, and appending the lists of the product_status objects by key.
func (c *Config) splitAdvisory(advisory *csaf.Advisory) ([]splitFile, error) {
	doc := *advisory
	var branches csaf.Branches
	var relationships csaf.Relationships
	if pt := advisory.ProductTree; pt != nil {
		branches = pt.Branches
		relationships = lo.FromPtr(pt.RelationShips)
		rest := *pt
		rest.Branches = nil
		rest.RelationShips = nil
		doc.ProductTree = &rest
	}

	// Relationships are a flat list, so only the list itself can be halved.
	// splitArray calls splitItem only for a single relationship that exceeds the limit on its own, which has no smaller parts, so it always fails, naming the relationship.
	relationshipParts, err := splitArray(relationships, c.maxFileSize, func(r *csaf.Relationship) (csaf.Relationships, error) {
		var id csaf.ProductID
		if r != nil && r.FullProductName != nil {
			id = lo.FromPtr(r.FullProductName.ProductID)
		}
		return nil, xerrors.Errorf("relationship %q cannot be split", id)
	})
	if err != nil {
		return nil, xerrors.Errorf("failed to split relationships: %w", err)
	}

	branchParts, err := splitArray(branches, c.maxFileSize, splitBranch)
	if err != nil {
		return nil, xerrors.Errorf("failed to split branches: %w", err)
	}

	var vulnFiles []splitFile
	if advisory.Vulnerabilities != nil {
		// The vulnerabilities are replaced with copies without the product arrays, so the advisory itself is not changed; a null vulnerability stays null.
		doc.Vulnerabilities = make(csaf.Vulnerabilities, len(advisory.Vulnerabilities))
	}
	for i, v := range advisory.Vulnerabilities {
		if v == nil {
			continue
		}
		rest, files, err := c.splitVulnerability(fmt.Sprintf("vulnerabilities-%04d", i+1), v)
		if err != nil {
			return nil, xerrors.Errorf("failed to split vulnerability %q: %w", lo.FromPtr(v.CVE), err)
		}
		doc.Vulnerabilities[i] = rest
		vulnFiles = append(vulnFiles, files...)
	}

	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, xerrors.Errorf("json marshal error: %w", err)
	}
	if len(b) > c.maxFileSize {
		return nil, xerrors.Errorf("document.json is %d bytes, over the %d byte limit", len(b), c.maxFileSize)
	}

	files := []splitFile{{path: "document.json", data: b}}
	files = append(files, numberedFiles("branches", branchParts)...)
	files = append(files, numberedFiles("relationships", relationshipParts)...)
	files = append(files, vulnFiles...)
	return files, nil
}

// splitVulnerability moves the arrays that list products out of a vulnerability, prefixing their file names with prefix:
//   - <prefix>-product_status-NNNN.json hold product_status, or one list per file if it exceeds the limit (see splitProductStatus);
//   - <prefix>-scores-NNNN.json, <prefix>-threats-NNNN.json, <prefix>-flags-NNNN.json and <prefix>-remediations-NNNN.json hold these arrays, split by splitArray and splitByProducts.
//
// It returns the vulnerability without these arrays, and the files holding them.
func (c *Config) splitVulnerability(prefix string, v *csaf.Vulnerability) (*csaf.Vulnerability, []splitFile, error) {
	type array struct {
		name  string
		split func() ([][]byte, error)
	}
	arrays := []array{
		{name: "product_status", split: func() ([][]byte, error) {
			return splitProductStatus(v.ProductStatus, c.maxFileSize)
		}},
		{name: "scores", split: func() ([][]byte, error) {
			return splitArray(v.Scores, c.maxFileSize, splitByProducts[csaf.Scores](func(s *csaf.Score) **csaf.Products { return &s.Products }))
		}},
		{name: "threats", split: func() ([][]byte, error) {
			return splitArray(v.Threats, c.maxFileSize, splitByProducts[csaf.Threats](func(t *csaf.Threat) **csaf.Products { return &t.ProductIds }))
		}},
		{name: "flags", split: func() ([][]byte, error) {
			return splitArray(v.Flags, c.maxFileSize, splitByProducts[csaf.Flags](func(f *csaf.Flag) **csaf.Products { return &f.ProductIds }))
		}},
		{name: "remediations", split: func() ([][]byte, error) {
			return splitArray(v.Remediations, c.maxFileSize, splitByProducts[csaf.Remediations](func(r *csaf.Remediation) **csaf.Products { return &r.ProductIds }))
		}},
	}

	var files []splitFile
	for _, a := range arrays {
		parts, err := a.split()
		if err != nil {
			return nil, nil, xerrors.Errorf("failed to split %s: %w", a.name, err)
		}
		files = append(files, numberedFiles(prefix+"-"+a.name, parts)...)
	}

	rest := *v
	rest.ProductStatus = nil
	rest.Scores = nil
	rest.Threats = nil
	rest.Flags = nil
	rest.Remediations = nil
	return &rest, files, nil
}

// productStatusList is a list of product_status, named as in JSON.
type productStatusList struct {
	name string
	list func(*csaf.ProductStatus) **csaf.Products
}

// productStatusLists are all lists of product_status, in the order of their JSON fields.
var productStatusLists = []productStatusList{
	{name: "first_affected", list: func(s *csaf.ProductStatus) **csaf.Products { return &s.FirstAffected }},
	{name: "first_fixed", list: func(s *csaf.ProductStatus) **csaf.Products { return &s.FirstFixed }},
	{name: "fixed", list: func(s *csaf.ProductStatus) **csaf.Products { return &s.Fixed }},
	{name: "known_affected", list: func(s *csaf.ProductStatus) **csaf.Products { return &s.KnownAffected }},
	{name: "known_not_affected", list: func(s *csaf.ProductStatus) **csaf.Products { return &s.KnownNotAffected }},
	{name: "last_affected", list: func(s *csaf.ProductStatus) **csaf.Products { return &s.LastAffected }},
	{name: "recommended", list: func(s *csaf.ProductStatus) **csaf.Products { return &s.Recommended }},
	{name: "under_investigation", list: func(s *csaf.ProductStatus) **csaf.Products { return &s.UnderInvestigation }},
}

// splitProductStatus marshals a product_status as an indented JSON object and, if it exceeds maxSize, splits it into product_status objects holding one list each, in the order of their JSON fields, so appending the lists of the objects in order restores the product_status.
// A list is not split further: a list that exceeds maxSize on its own is an error.
// Reading the objects back by appending their lists also works if a list is split into several objects in the future.
func splitProductStatus(s *csaf.ProductStatus, maxSize int) ([][]byte, error) {
	if s == nil {
		return nil, nil
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, xerrors.Errorf("json marshal error: %w", err)
	}
	if len(b) <= maxSize {
		return [][]byte{b}, nil
	}

	var parts [][]byte
	for _, l := range productStatusLists {
		ids := *l.list(s)
		if len(lo.FromPtr(ids)) == 0 {
			continue
		}
		var part csaf.ProductStatus
		*l.list(&part) = ids
		b, err := json.MarshalIndent(&part, "", "  ")
		if err != nil {
			return nil, xerrors.Errorf("json marshal error: %w", err)
		}
		if len(b) > maxSize {
			return nil, xerrors.Errorf("%s is %d bytes, over the %d byte limit", l.name, len(b), maxSize)
		}
		parts = append(parts, b)
	}
	return parts, nil
}

// splitArray marshals items as an indented JSON array and, while it exceeds maxSize, halves it recursively.
// A single item that exceeds maxSize on its own is replaced with the pieces returned by splitItem, which returns an error if the item cannot be split.
// The returned arrays hold the items in their original order.
func splitArray[S ~[]E, E any](items S, maxSize int, splitItem func(E) (S, error)) ([][]byte, error) {
	if len(items) == 0 {
		return nil, nil
	}
	b, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return nil, xerrors.Errorf("json marshal error: %w", err)
	}
	if len(b) <= maxSize {
		return [][]byte{b}, nil
	}

	if len(items) == 1 {
		pieces, err := splitItem(items[0])
		if err != nil {
			return nil, xerrors.Errorf("a single item is %d bytes, over the %d byte limit: %w", len(b), maxSize, err)
		}
		return splitArray(pieces, maxSize, splitItem)
	}

	mid := len(items) / 2
	left, err := splitArray(items[:mid], maxSize, splitItem)
	if err != nil {
		return nil, err
	}
	right, err := splitArray(items[mid:], maxSize, splitItem)
	if err != nil {
		return nil, err
	}
	return append(left, right...), nil
}

// splitBranch splits a branch into smaller branches with the same category, name and product, each holding a part of its child branches.
// A branch with a single child branch is split into copies holding the pieces of that child.
// A branch without child branches cannot be split, and an error is returned for it.
func splitBranch(b *csaf.Branch) (csaf.Branches, error) {
	if b == nil {
		return nil, xerrors.New("null branch cannot be split")
	}
	wrap := func(children csaf.Branches) *csaf.Branch {
		return &csaf.Branch{
			Category: b.Category,
			Name:     b.Name,
			Product:  b.Product,
			Branches: children,
		}
	}

	switch len(b.Branches) {
	case 0:
		return nil, xerrors.Errorf("%s branch %q has no child branches to split", lo.FromPtr(b.Category), lo.FromPtr(b.Name))
	case 1:
		pieces, err := splitBranch(b.Branches[0])
		if err != nil {
			return nil, err
		}
		return lo.Map(pieces, func(p *csaf.Branch, _ int) *csaf.Branch {
			return wrap(csaf.Branches{p})
		}), nil
	default:
		mid := len(b.Branches) / 2
		return csaf.Branches{wrap(b.Branches[:mid]), wrap(b.Branches[mid:])}, nil
	}
}

// splitByProducts returns a splitItem function for splitArray that splits an entry of scores, threats, flags or remediations into two copies, each holding a half of its product list.
// products returns the entry's product list field.
// Everything else, group IDs included, is kept in both copies, so the copies differ only in their product lists.
// An entry with fewer than two products cannot be split, and an error is returned for it.
func splitByProducts[S ~[]*E, E any](products func(*E) **csaf.Products) func(*E) (S, error) {
	return func(e *E) (S, error) {
		if e == nil {
			return nil, xerrors.New("null entry cannot be split")
		}
		list := lo.FromPtr(*products(e))
		if len(list) < 2 {
			return nil, xerrors.Errorf("an entry with %d product(s) cannot be split", len(list))
		}
		mid := len(list) / 2
		leftList, rightList := list[:mid], list[mid:]
		left, right := *e, *e
		*products(&left) = &leftList
		*products(&right) = &rightList
		return S{&left, &right}, nil
	}
}

// numberedFiles names parts as <prefix>-0001.json, <prefix>-0002.json, and so on.
func numberedFiles(prefix string, parts [][]byte) []splitFile {
	return lo.Map(parts, func(data []byte, i int) splitFile {
		return splitFile{path: fmt.Sprintf("%s-%04d.json", prefix, i+1), data: data}
	})
}

// removeIfExists removes path, ignoring a missing file.
func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return xerrors.Errorf("failed to remove %s: %w", path, err)
	}
	return nil
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
		// path is like "2025/cve-2025-22868.json".
		// It is validated before anything is removed, since the <cve-id>/ directory is removed recursively.
		if !deletionPathRegex.MatchString(entry.Path) {
			return xerrors.Errorf("invalid path in deletions.csv: %q", entry.Path)
		}
		// The document may be stored as either <cve-id>.json or the <cve-id>/ directory (see saveAdvisory), so remove both.
		filePath := filepath.Join(c.baseDir, entry.Path)
		if err := removeIfExists(filePath); err != nil {
			return err
		}
		splitDir := strings.TrimSuffix(filePath, filepath.Ext(filePath))
		if err := os.RemoveAll(splitDir); err != nil {
			return xerrors.Errorf("failed to remove %s: %w", splitDir, err)
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

	if err = c.saveAdvisory(cveID, advisory); err != nil {
		return xerrors.Errorf("failed to save advisory: %w", err)
	}

	return nil
}

// cveIDPattern matches CVE IDs in file names like "cve-2025-22868", capturing the year.
const cveIDPattern = `cve-(\d{4})-\d{4,}`

// cveIDRegex matches a whole CVE ID.
// It is checked before the CVE ID is used in paths, since an existing split directory under it is removed recursively.
var cveIDRegex = regexp.MustCompile(`^` + cveIDPattern + `$`)

// deletionPathRegex matches paths in deletions.csv like "2025/cve-2025-22868.json".
var deletionPathRegex = regexp.MustCompile(`^\d{4}/` + cveIDPattern + `\.json$`)

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
