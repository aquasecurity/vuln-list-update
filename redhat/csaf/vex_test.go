package csaf_test

import (
	"archive/tar"
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
		wantFiles    []string
		wantErr      string
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
			wantFiles: []string{
				"2024/cve-2024-9999.json", // proves archive download was skipped
			},
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

			c := csaf.NewConfig(csaf.WithBaseDir(baseDir), csaf.WithBaseURL(lo.Must(url.Parse(ts.URL))),
				csaf.WithRetry(0))

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
