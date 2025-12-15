package csaf_test

import (
	"archive/tar"
	"bytes"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		metadataFile string // txtar for metadata (archive_latest.txt, CSVs) and delta files
		existingFile string // txtar for existing local data (to verify archive skip)
		wantFiles    []string
		wantErr      string
	}{
		{
			name:         "first run - archive only",
			archiveFile:  "testdata/archive.txtar",
			metadataFile: "testdata/happy.txtar",
			wantFiles: []string{
				"2024/cve-2024-0001.json",
			},
		},
		{
			name:         "delta update - changes only",
			archiveFile:  "testdata/archive.txtar",
			metadataFile: "testdata/delta_changes.txtar",
			existingFile: "testdata/existing.txtar",
			wantFiles: []string{
				"2024/cve-2024-0001.json", // from existing data
				"2024/cve-2024-0002.json", // from changes.csv
				"2024/cve-2024-9999.json", // proves archive download was skipped
			},
		},
		{
			name:         "delta update - deletions only",
			archiveFile:  "testdata/archive.txtar",
			metadataFile: "testdata/delta_deletions.txtar",
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
			name:         "invalid csaf",
			archiveFile:  "testdata/invalid.txtar",
			metadataFile: "testdata/invalid.txtar",
			wantErr:      "'category' is missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse archive txtar for creating .tar.zst
			var archiveAr *txtar.Archive
			if tt.archiveFile != "" {
				archiveAr = parseTxtar(t, tt.archiveFile)
			}

			// Parse metadata txtar for serving files
			var metadataFsys fs.FS
			if tt.metadataFile != "" {
				metadataAr := parseTxtar(t, tt.metadataFile)
				var err error
				metadataFsys, err = txtar.FS(metadataAr)
				require.NoError(t, err)
			}

			tmpDir := t.TempDir()
			createTestArchive(t, archiveAr, tmpDir)

			// Setup test server
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Handle archive separately (can't be in txtar)
				if strings.HasSuffix(r.URL.Path, ".tar.zst") {
					http.ServeFile(w, r, filepath.Join(tmpDir, archiveName))
					return
				}

				// Serve everything else from metadata txtar FS
				if metadataFsys != nil {
					http.ServeFileFS(w, r, metadataFsys, strings.TrimPrefix(r.URL.Path, "/"))
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer ts.Close()

			// Set up VulnListDir for last_updated.json
			vulnListDir := t.TempDir()
			utils.SetVulnListDir(vulnListDir)
			baseDir := filepath.Join(vulnListDir, "csaf-vex")

			// If existingFile is set, populate baseDir and set last_updated
			// This simulates existing local data that is NOT in the archive
			if tt.existingFile != "" {
				existingAr := parseTxtar(t, tt.existingFile)
				populateTestData(t, existingAr, baseDir)
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

			gotFiles := collectFiles(t, baseDir)
			require.ElementsMatch(t, tt.wantFiles, gotFiles)
		})
	}
}

func collectFiles(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		if d.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(dir, path)
		require.NoError(t, err)
		files = append(files, relPath)
		return nil
	})
	require.NoError(t, err)
	return files
}

func parseTxtar(t *testing.T, path string) *txtar.Archive {
	t.Helper()
	ar, err := txtar.ParseFile(path)
	require.NoError(t, err)
	return ar
}

func createTestArchive(t *testing.T, ar *txtar.Archive, tmpDir string) {
	t.Helper()
	if ar == nil {
		return
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Add only JSON files from txtar archive to tar
	for _, f := range ar.Files {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		hdr := &tar.Header{
			Name: f.Name,
			Mode: 0644,
			Size: int64(len(f.Data)),
		}
		require.NoError(t, tw.WriteHeader(hdr))
		_, err := tw.Write(f.Data)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())

	var compressedBuf bytes.Buffer
	enc, err := zstd.NewWriter(&compressedBuf)
	require.NoError(t, err)

	_, err = enc.Write(buf.Bytes())
	require.NoError(t, err)
	require.NoError(t, enc.Close())

	err = os.WriteFile(filepath.Join(tmpDir, archiveName), compressedBuf.Bytes(), 0644)
	require.NoError(t, err)
}

// populateTestData copies files from txtar to baseDir.
func populateTestData(t *testing.T, ar *txtar.Archive, baseDir string) {
	t.Helper()
	fsys, err := txtar.FS(ar)
	require.NoError(t, err)
	require.NoError(t, os.CopyFS(baseDir, fsys))
}
