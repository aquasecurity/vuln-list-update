package csaf_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
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

	"github.com/klauspost/compress/zstd"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/txtar"

	"github.com/aquasecurity/vuln-list-update/redhat/csaf"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const archiveName = "csaf_vex_2025-12-06.tar.zst"

func TestConfig_Update(t *testing.T) {
	tests := []struct {
		name         string
		archiveFile  string // txtar for archive content
		serverFile   string // txtar for files served by the test server
		existingFile string // txtar for existing local data, includes cve-2024-9999.json to verify archive skip
		// staleFiles are created in the base dir with the content "stale" before the update, simulating a representation of a CVE left behind by an earlier run.
		// A path nested under a file name, such as "x.json.gz/stale", turns that name into a non-empty directory that cannot be removed.
		staleFiles  []string
		maxFileSize int // 0 keeps the default
		wantFiles   []string
		// wantFullVuln lists the files whose vulnerability keeps product_status, scores and flags.
		wantFullVuln []string
		// wantContent maps a file to a golden file with its expected content, decompressed for .json.gz.
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
			wantFullVuln: []string{"2024/cve-2024-0002.json"},
			wantContent:  map[string]string{"2024/cve-2024-0002.json": "testdata/golden/cve-2024-0002.json"},
		},
		{
			// cve-2024-0002 is 3530 bytes indented.
			name:        "oversized document is gzip-compressed",
			archiveFile: "testdata/archive.txtar",
			serverFile:  "testdata/first_run.txtar",
			maxFileSize: 3000,
			wantFiles: []string{
				"2024/cve-2024-0001.json",
				"2024/cve-2024-0002.json.gz",
			},
			wantFullVuln: []string{"2024/cve-2024-0002.json.gz"},
			// The compressed document is identical to the one written uncompressed.
			wantContent: map[string]string{"2024/cve-2024-0002.json.gz": "testdata/golden/cve-2024-0002.json"},
		},
		{
			name:         "oversized document replaces stale .json",
			serverFile:   "testdata/first_run.txtar",
			existingFile: "testdata/existing.txtar",
			staleFiles:   []string{"2024/cve-2024-0002.json"},
			maxFileSize:  3000,
			wantFiles: []string{
				"2024/cve-2024-0001.json",
				"2024/cve-2024-0002.json.gz",
				"2024/cve-2024-9999.json",
			},
			wantFullVuln: []string{"2024/cve-2024-0002.json.gz"},
		},
		{
			name:         "small document replaces stale .json.gz",
			serverFile:   "testdata/first_run.txtar",
			existingFile: "testdata/existing.txtar",
			staleFiles:   []string{"2024/cve-2024-0002.json.gz"},
			wantFiles: []string{
				"2024/cve-2024-0001.json",
				"2024/cve-2024-0002.json",
				"2024/cve-2024-9999.json",
			},
			wantFullVuln: []string{"2024/cve-2024-0002.json"},
		},
		{
			// A document exactly at the limit still fits and is written uncompressed.
			name:         "document at the limit replaces stale .json.gz",
			serverFile:   "testdata/first_run.txtar",
			existingFile: "testdata/existing.txtar",
			staleFiles:   []string{"2024/cve-2024-0002.json.gz"},
			maxFileSize:  3530,
			wantFiles: []string{
				"2024/cve-2024-0001.json",
				"2024/cve-2024-0002.json",
				"2024/cve-2024-9999.json",
			},
			wantFullVuln: []string{"2024/cve-2024-0002.json"},
		},
		{
			name:         "document too large even gzip-compressed",
			serverFile:   "testdata/first_run.txtar",
			existingFile: "testdata/existing.txtar",
			maxFileSize:  1,
			wantErr:      "too large even gzip-compressed",
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
			staleFiles:   []string{"2024/cve-2024-0001.json.gz"}, // removed along with cve-2024-0001.json
			wantFiles: []string{
				"2024/cve-2024-9999.json", // proves archive download was skipped
			},
		},
		{
			name:         "stale representation cannot be removed",
			serverFile:   "testdata/first_run.txtar",
			existingFile: "testdata/existing.txtar",
			staleFiles:   []string{"2024/cve-2024-0002.json.gz/stale"},
			wantErr:      "failed to remove",
		},
		{
			name:         "deleted document cannot be removed",
			serverFile:   "testdata/delta_deletions.txtar",
			existingFile: "testdata/existing.txtar",
			staleFiles:   []string{"2024/cve-2024-0001.json.gz/stale"},
			wantErr:      "failed to apply deletions: failed to remove",
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
				require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
				require.NoError(t, os.WriteFile(p, []byte("stale"), 0o644))
			}

			opts := []csaf.Option{csaf.WithBaseDir(baseDir), csaf.WithBaseURL(lo.Must(url.Parse(ts.URL))),
				csaf.WithRetry(0)}
			if tt.maxFileSize > 0 {
				opts = append(opts, csaf.WithMaxFileSize(tt.maxFileSize))
			}
			c := csaf.NewConfig(opts...)

			err := c.Update()
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
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
				if strings.HasSuffix(relPath, ".gz") {
					zr, err := gzip.NewReader(bytes.NewReader(b))
					require.NoError(t, err, relPath)
					// The header carries no name or modification time, so unchanged documents produce no diff.
					assert.Empty(t, zr.Name, relPath)
					assert.True(t, zr.ModTime.IsZero(), relPath)
					b, err = io.ReadAll(zr)
					require.NoError(t, err, relPath)
				}
				assert.True(t, json.Valid(b), relPath)
				if golden, ok := tt.wantContent[relPath]; ok {
					want, err := os.ReadFile(golden)
					require.NoError(t, err)
					assert.Equal(t, string(want), string(b), relPath)
				}

				// Documents are stored whole, also when gzip-compressed.
				for _, field := range []string{`"product_status"`, `"scores"`, `"flags"`} {
					if slices.Contains(tt.wantFullVuln, relPath) {
						assert.Contains(t, string(b), field, relPath)
					} else {
						assert.NotContains(t, string(b), field, relPath)
					}
				}
				// Documents are always written indented, also when gzip-compressed.
				assert.Contains(t, string(b), "\n  ", relPath)
				return nil
			})
			require.NoError(t, err)
			assert.Len(t, gotFiles, len(tt.wantFiles))
		})
	}
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
