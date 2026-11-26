package csaf_test

import (
	"archive/tar"
	"encoding/json"
	"flag"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	gocsaf "github.com/gocsaf/csaf/v3/csaf"
	"github.com/klauspost/compress/zstd"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/txtar"

	"github.com/aquasecurity/vuln-list-update/redhat/csaf"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const archiveName = "csaf_vex_2025-12-06.tar.zst"

var update = flag.Bool("update", false, "update golden files")

func TestConfig_Update(t *testing.T) {
	tests := []struct {
		name         string
		archiveFile  string // txtar for archive content
		serverFile   string // txtar for files served by the test server
		existingFile string // txtar for existing local data, includes cve-2024-9999.json to verify archive skip
		// staleFiles are created in the base dir with the content "stale" before the update, simulating a representation of a CVE left behind by an earlier run.
		// A path nested under a file name, such as "x.json/stale", turns that name into a non-empty directory that cannot be removed.
		staleFiles  []string
		maxFileSize int // 0 keeps the default
		wantFiles   []string
		// wantContent maps a file to a golden file with its expected content.
		wantContent map[string]string
		wantErr     string
	}{
		{
			name:        "first run",
			archiveFile: "testdata/archive.txtar",
			serverFile:  "testdata/first_run.txtar",
			wantFiles: []string{
				"2024/cve-2024-0001.json", // from archive
				"2024/cve-2024-0002.json", // from changes.csv
				// cve-2024-0003.json deleted by deletions.csv
			},
			wantContent: map[string]string{"2024/cve-2024-0002.json": "testdata/golden/cve-2024-0002.json"},
		},
		{
			// cve-2024-0002 is 3530 bytes indented.
			// How documents are split is covered by TestConfig_SplitAdvisory.
			name:        "oversized document is split",
			archiveFile: "testdata/archive.txtar",
			serverFile:  "testdata/first_run.txtar",
			maxFileSize: 3000,
			wantFiles: []string{
				"2024/cve-2024-0001.json",
				"2024/cve-2024-0002/document.json",
				"2024/cve-2024-0002/branches-0001.json",
				"2024/cve-2024-0002/vulnerabilities-0001-product_status-0001.json",
				"2024/cve-2024-0002/vulnerabilities-0001-scores-0001.json",
				"2024/cve-2024-0002/vulnerabilities-0001-flags-0001.json",
			},
		},
		{
			name:         "oversized document replaces stale .json",
			serverFile:   "testdata/first_run.txtar",
			existingFile: "testdata/existing.txtar",
			// Parts of an earlier, larger split are removed.
			staleFiles:  []string{"2024/cve-2024-0002.json", "2024/cve-2024-0002/branches-0002.json"},
			maxFileSize: 3000,
			wantFiles: []string{
				"2024/cve-2024-0001.json",
				"2024/cve-2024-0002/document.json",
				"2024/cve-2024-0002/branches-0001.json",
				"2024/cve-2024-0002/vulnerabilities-0001-product_status-0001.json",
				"2024/cve-2024-0002/vulnerabilities-0001-scores-0001.json",
				"2024/cve-2024-0002/vulnerabilities-0001-flags-0001.json",
				"2024/cve-2024-9999.json",
			},
		},
		{
			name:         "small document replaces stale split directory",
			serverFile:   "testdata/first_run.txtar",
			existingFile: "testdata/existing.txtar",
			staleFiles:   []string{"2024/cve-2024-0002/document.json"},
			wantFiles: []string{
				"2024/cve-2024-0001.json",
				"2024/cve-2024-0002.json",
				"2024/cve-2024-9999.json",
			},
		},
		{
			// A document exactly at the limit still fits and is written whole.
			name:         "document at the limit replaces stale split directory",
			serverFile:   "testdata/first_run.txtar",
			existingFile: "testdata/existing.txtar",
			staleFiles:   []string{"2024/cve-2024-0002/document.json"},
			maxFileSize:  3530,
			wantFiles: []string{
				"2024/cve-2024-0001.json",
				"2024/cve-2024-0002.json",
				"2024/cve-2024-9999.json",
			},
		},
		{
			name:         "document cannot be split",
			serverFile:   "testdata/first_run.txtar",
			existingFile: "testdata/existing.txtar",
			staleFiles:   []string{"2024/cve-2024-0002.json"}, // left untouched
			maxFileSize:  1,
			wantErr:      "failed to split cve-2024-0002",
		},
		{
			name:         "document cannot be split, stale split directory left untouched",
			serverFile:   "testdata/first_run.txtar",
			existingFile: "testdata/existing.txtar",
			staleFiles:   []string{"2024/cve-2024-0002/document.json", "2024/cve-2024-0002/branches-0001.json"},
			maxFileSize:  1,
			wantErr:      "failed to split cve-2024-0002",
		},
		{
			name:         "delta update - changes only",
			serverFile:   "testdata/delta_changes.txtar",
			existingFile: "testdata/existing.txtar",
			wantFiles: []string{
				"2024/cve-2024-0001.json", // from existing data
				"2024/cve-2024-0002.json", // from changes.csv
				"2024/cve-2024-9999.json", // proves archive download was skipped
			},
		},
		{
			name:         "delta update - deletions only",
			serverFile:   "testdata/delta_deletions.txtar",
			existingFile: "testdata/existing.txtar",
			staleFiles:   []string{"2024/cve-2024-0001/document.json"}, // removed along with cve-2024-0001.json
			wantFiles: []string{
				"2024/cve-2024-9999.json", // proves archive download was skipped
			},
		},
		{
			name:         "stale representation cannot be removed",
			serverFile:   "testdata/first_run.txtar",
			existingFile: "testdata/existing.txtar",
			staleFiles:   []string{"2024/cve-2024-0002.json/stale"},
			wantErr:      "failed to remove",
		},
		{
			name:         "deleted document cannot be removed",
			serverFile:   "testdata/delta_deletions.txtar",
			existingFile: "testdata/existing.txtar",
			staleFiles:   []string{"2024/cve-2024-0001.json/stale"},
			wantErr:      "failed to apply deletions: failed to remove",
		},
		{
			name:         "invalid path in deletions.csv",
			serverFile:   "testdata/delta_deletions_invalid.txtar",
			existingFile: "testdata/existing.txtar",
			wantErr:      `failed to apply deletions: invalid path in deletions.csv: "2024/../cve-2024-0001.json"`,
		},
		{
			name:    "404",
			wantErr: "failed to fetch VEX archive: failed to fetch URL",
		},
		{
			name:        "invalid csaf",
			archiveFile: "testdata/invalid.txtar",
			serverFile:  "testdata/invalid.txtar",
			wantErr:     "'category' is missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			archiveFsys := parseTxtar(t, tt.archiveFile)
			archivePath := createTestArchive(t, archiveFsys)
			serverFsys := parseTxtar(t, tt.serverFile)

			// Setup test server
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Handle archive separately (can't be in txtar)
				if strings.HasSuffix(r.URL.Path, ".tar.zst") {
					http.ServeFile(w, r, archivePath)
					return
				}
				http.ServeFileFS(w, r, serverFsys, strings.TrimPrefix(r.URL.Path, "/"))
			}))
			defer ts.Close()

			// Set up VulnListDir for last_updated.json
			vulnListDir := t.TempDir()
			utils.SetVulnListDir(vulnListDir)
			baseDir := filepath.Join(vulnListDir, "csaf-vex")

			// If existingFile is set, populate baseDir and set last_updated
			// This simulates existing local data that is NOT in the archive
			if tt.existingFile != "" {
				existingFsys := parseTxtar(t, tt.existingFile)
				populateTestData(t, existingFsys, baseDir)
				// Set last_updated to a time before the CSV entries (2025-12-10)
				// so that delta update will process them
				err := utils.SetLastUpdatedDate("csaf-vex", time.Date(2025, 12, 5, 0, 0, 0, 0, time.UTC))
				require.NoError(t, err)
			}
			for _, f := range tt.staleFiles {
				p := filepath.Join(baseDir, f)
				// A stale file nested under an existing file replaces that file with a directory.
				if fi, err := os.Stat(filepath.Dir(p)); err == nil && !fi.IsDir() {
					require.NoError(t, os.Remove(filepath.Dir(p)))
				}
				require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
				require.NoError(t, os.WriteFile(p, []byte("stale"), 0o644))
			}

			opts := []csaf.Option{
				csaf.WithBaseDir(baseDir), csaf.WithBaseURL(lo.Must(url.Parse(ts.URL))),
				csaf.WithRetry(0),
			}
			if tt.maxFileSize > 0 {
				opts = append(opts, csaf.WithMaxFileSize(tt.maxFileSize))
			}
			c := csaf.NewConfig(opts...)

			err := c.Update()
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				// Stale files are left untouched on error.
				for _, f := range tt.staleFiles {
					b, err := os.ReadFile(filepath.Join(baseDir, f))
					require.NoError(t, err, f)
					assert.Equal(t, "stale", string(b), f)
				}
				return
			}
			require.NoError(t, err, tt.name)

			var gotFiles []string
			err = filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
				require.NoError(t, err)
				if info.IsDir() {
					return nil
				}
				relPath, err := filepath.Rel(baseDir, path)
				require.NoError(t, err)
				require.True(t, slices.Contains(tt.wantFiles, relPath), relPath)
				gotFiles = append(gotFiles, relPath)

				b, err := os.ReadFile(path)
				require.NoError(t, err)
				assert.True(t, json.Valid(b), relPath)
				if golden, ok := tt.wantContent[relPath]; ok {
					want, err := os.ReadFile(golden)
					require.NoError(t, err)
					assert.Equal(t, string(want), string(b), relPath)
				}

				// Documents are always written indented, also when split.
				assert.Contains(t, string(b), "\n  ", relPath)
				return nil
			})
			require.NoError(t, err)
			assert.Len(t, gotFiles, len(tt.wantFiles))
		})
	}
}

func TestConfig_SplitAdvisory(t *testing.T) {
	// testdata/split/advisory.json is 19267 bytes indented: document.json is 2396 bytes, branches are 6195 bytes, relationships are 4655 bytes, and the product arrays of the vulnerability are 1045 bytes or less each (see TestConfig_SplitVulnerability).
	// The vendor branch is the only top-level branch, so its child branches are halved.
	tests := []struct {
		name        string
		prepare     func(*gocsaf.Advisory) // modifies the advisory before it is split
		maxFileSize int
		wantDir     string // directory with the expected files
		wantErr     string
	}{
		{
			name:        "branches in 1 file",
			maxFileSize: 6200,
			wantDir:     "testdata/split/1-branches",
		},
		{
			name:        "branches in 2 files",
			maxFileSize: 5000,
			wantDir:     "testdata/split/2-branches",
		},
		{
			name:        "relationships in 2 files",
			maxFileSize: 4500,
			wantDir:     "testdata/split/2-relationships",
		},
		{
			name:        "branches in 4 files",
			maxFileSize: 2850,
			wantDir:     "testdata/split/4-branches",
		},
		{
			name:        "no branches",
			prepare:     func(a *gocsaf.Advisory) { a.ProductTree.Branches = nil },
			maxFileSize: 5000,
			wantDir:     "testdata/split/no-branches",
		},
		{
			name:        "no relationships",
			prepare:     func(a *gocsaf.Advisory) { a.ProductTree.RelationShips = nil },
			maxFileSize: 5000,
			wantDir:     "testdata/split/no-relationships",
		},
		{
			// The vendor branch has a single child branch, so the split goes down to its children and wraps each half in copies of both branches.
			name: "branch with a single child branch",
			prepare: func(a *gocsaf.Advisory) {
				vendor := a.ProductTree.Branches[0]
				vendor.Branches = gocsaf.Branches{
					{
						Category: lo.ToPtr(gocsaf.CSAFBranchCategoryProductFamily),
						Name:     lo.ToPtr("Red Hat Enterprise Linux"),
						Branches: vendor.Branches,
					},
				}
			},
			maxFileSize: 5000,
			wantDir:     "testdata/split/single-child",
		},
		{
			// The vulnerabilities are numbered by their position in the document, so the files of the third one are vulnerabilities-0003-*, and the null one stays null in document.json.
			name: "several vulnerabilities",
			prepare: func(a *gocsaf.Advisory) {
				second := *a.Vulnerabilities[0]
				second.CVE = lo.ToPtr(gocsaf.CVE("CVE-2024-0003"))
				second.Flags = nil
				second.Remediations = nil
				a.Vulnerabilities = append(a.Vulnerabilities, nil, &second)
			},
			maxFileSize: 6200,
			wantDir:     "testdata/split/several-vulnerabilities",
		},
		{
			name:        "relationship too large to split",
			maxFileSize: 100,
			wantErr:     `failed to split relationships: a single item is 376 bytes, over the 100 byte limit: relationship "red_hat_enterprise_linux_9:kernel-0:5.14.0-1.el9.x86_64" cannot be split`,
		},
		{
			name:        "branch too large to split",
			maxFileSize: 500,
			wantErr:     `failed to split branches: a single item is 602 bytes, over the 500 byte limit: product_name branch "Red Hat Enterprise Linux 9" has no child branches to split`,
		},
		{
			name:        "document.json too large",
			maxFileSize: 1000,
			wantErr:     "document.json is 2396 bytes, over the 1000 byte limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := os.ReadFile("testdata/split/advisory.json")
			require.NoError(t, err)
			var advisory gocsaf.Advisory
			require.NoError(t, json.Unmarshal(b, &advisory))
			if tt.prepare != nil {
				tt.prepare(&advisory)
			}

			c := csaf.NewConfig(csaf.WithMaxFileSize(tt.maxFileSize))
			got, err := c.SplitAdvisory(&advisory)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assertGoldenDir(t, tt.wantDir, got)
			assertSameProductIDs(t, productIDs(&advisory), &advisory, got)
		})
	}
}

func TestConfig_SplitVulnerability(t *testing.T) {
	// A separate test from TestConfig_SplitAdvisory: there, document.json alone is larger than any of these arrays, so a limit small enough to split them fails on document.json first.
	// The vulnerability of testdata/split/advisory.json has these arrays, indented: product_status 860 bytes with fixed and known_not_affected (6 product IDs each, 426 and 436 bytes as separate product_status objects), scores 1045 bytes (a single score with 12 products), threats 927 bytes (a single threat with 12 products), flags 498 bytes, remediations 840 bytes (2 remediations with 3 products each).
	tests := []struct {
		name        string
		prepare     func(*gocsaf.Vulnerability) // modifies the vulnerability before it is split
		maxFileSize int
		wantDir     string // directory with the expected files
		wantErr     string
	}{
		{
			name:        "arrays not split",
			maxFileSize: 1045,
			wantDir:     "testdata/split/vulnerability/not-split",
		},
		{
			// Every array is split: product_status into one list per file, the remediations into halves, the single flag into 2 copies with 3 products each, and the single score and threat into 4 copies with 3 products each, since a copy with 6 products is still too large.
			name:        "entries split by products",
			maxFileSize: 450,
			wantDir:     "testdata/split/vulnerability/by-products",
		},
		{
			name:        "product_status list too large",
			maxFileSize: 430,
			wantErr:     "failed to split product_status: known_not_affected is 436 bytes, over the 430 byte limit",
		},
		{
			name:        "entry with a single product too large",
			prepare:     func(v *gocsaf.Vulnerability) { v.ProductStatus = nil },
			maxFileSize: 250,
			wantErr:     "failed to split scores: a single item is 274 bytes, over the 250 byte limit: an entry with 1 product(s) cannot be split",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := os.ReadFile("testdata/split/advisory.json")
			require.NoError(t, err)
			var advisory gocsaf.Advisory
			require.NoError(t, json.Unmarshal(b, &advisory))
			v := advisory.Vulnerabilities[0]
			if tt.prepare != nil {
				tt.prepare(v)
			}

			c := csaf.NewConfig(csaf.WithMaxFileSize(tt.maxFileSize))
			got, rest, err := c.SplitVulnerability("vulnerabilities-0001", v)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assertGoldenDir(t, tt.wantDir, got)
			assertSameProductIDs(t, productIDs(&advisory), v, got)

			// The arrays are moved out, and the rest of the vulnerability is kept.
			want := *v
			want.ProductStatus, want.Scores, want.Threats, want.Flags, want.Remediations = nil, nil, nil, nil, nil
			assert.Equal(t, &want, rest)
		})
	}
}

// productIDs returns the product IDs defined in the product tree of an advisory.
func productIDs(advisory *gocsaf.Advisory) map[string]bool {
	ids := map[string]bool{}
	var walk func(gocsaf.Branches)
	walk = func(branches gocsaf.Branches) {
		for _, b := range branches {
			if b == nil {
				continue
			}
			if b.Product != nil {
				ids[string(lo.FromPtr(b.Product.ProductID))] = true
			}
			walk(b.Branches)
		}
	}
	if pt := advisory.ProductTree; pt != nil {
		walk(pt.Branches)
		for _, r := range lo.FromPtr(pt.RelationShips) {
			if r != nil && r.FullProductName != nil {
				ids[string(lo.FromPtr(r.FullProductName.ProductID))] = true
			}
		}
	}
	return ids
}

// assertSameProductIDs checks that every product ID occurs as many times in the split files as in the original, so the split neither lost nor duplicated any product.
// Copies of split branches and entries repeat only their other fields, such as names and scores, so the counts match exactly.
func assertSameProductIDs(t *testing.T, ids map[string]bool, original any, files map[string]string) {
	t.Helper()
	count := func(data []byte, counts map[string]int) {
		var v any
		require.NoError(t, json.Unmarshal(data, &v))
		var walk func(any)
		walk = func(v any) {
			switch v := v.(type) {
			case string:
				if ids[v] {
					counts[v]++
				}
			case []any:
				for _, e := range v {
					walk(e)
				}
			case map[string]any:
				for _, e := range v {
					walk(e)
				}
			}
		}
		walk(v)
	}

	b, err := json.Marshal(original)
	require.NoError(t, err)
	want := map[string]int{}
	count(b, want)
	require.NotEmpty(t, want)

	got := map[string]int{}
	for _, data := range files {
		count([]byte(data), got)
	}
	assert.Equal(t, want, got)
}

// assertGoldenDir compares files with the files in dir, keyed by their names.
// With -update, dir is rewritten with files instead.
func assertGoldenDir(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	if *update {
		require.NoError(t, os.RemoveAll(dir))
		require.NoError(t, os.MkdirAll(dir, 0o755))
		for name, data := range files {
			require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644))
		}
	}

	want := map[string]string{}
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		require.NoError(t, err)
		want[e.Name()] = string(b)
	}
	assert.Equal(t, want, files)
}

func parseTxtar(t *testing.T, path string) fs.FS {
	t.Helper()
	if path == "" {
		return fstest.MapFS{}
	}
	ar, err := txtar.ParseFile(path)
	require.NoError(t, err)
	fsys, err := txtar.FS(ar)
	require.NoError(t, err)
	return fsys
}

func createTestArchive(t *testing.T, fsys fs.FS) string {
	t.Helper()
	archivePath := filepath.Join(t.TempDir(), archiveName)
	f, err := os.Create(archivePath)
	require.NoError(t, err)
	defer f.Close()

	zw, err := zstd.NewWriter(f)
	require.NoError(t, err)
	defer zw.Close()

	tw := tar.NewWriter(zw)
	defer tw.Close()

	require.NoError(t, tw.AddFS(fsys))

	return archivePath
}

func populateTestData(t *testing.T, fsys fs.FS, baseDir string) {
	t.Helper()
	require.NoError(t, os.CopyFS(baseDir, fsys))
}
