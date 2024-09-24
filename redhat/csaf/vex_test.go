package csaf

import (
	"archive/tar"
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const archiveName = "csaf_vex.tar.zst"

func TestConfig_Update(t *testing.T) {
	tests := []struct {
		name      string
		dir       string
		wantFiles []string
		wantErr   string
	}{
		{
			name: "happy path",
			dir:  "testdata/happy",
			wantFiles: []string{
				"2024/cve-2024-0208.json",
			},
		},
		{
			name:    "404",
			wantErr: "failed to fetch VEX archive: failed to fetch URL",
		},
		{
			name:    "invalid csaf",
			dir:     "testdata/invalid",
			wantErr: "'category' is missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			createTestArchive(t, tt.dir, tmpDir)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "archive_latest.txt") {
					w.Write([]byte(archiveName))
					return
				}
				http.ServeFile(w, r, filepath.Join(tmpDir, archiveName))
			}))
			defer ts.Close()

			baseDir := t.TempDir()
			c := NewConfig(
				WithBaseDir(baseDir),
				WithBaseURL(lo.Must(url.Parse(ts.URL))),
				WithRetry(0),
			)

			err := c.Update()
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err, tt.name)

			var fileCount int
			err = filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
				require.NoError(t, err)
				if info.IsDir() {
					return nil
				}
				fileCount++

				relPath, err := filepath.Rel(baseDir, path)
				require.NoError(t, err)
				require.True(t, slices.Contains(tt.wantFiles, relPath), relPath)
				return nil
			})
			assert.NoError(t, err, tt.name)
			assert.Equal(t, len(tt.wantFiles), fileCount, tt.name)
		})
	}
}

func createTestArchive(t *testing.T, dir, tmpDir string) {
	t.Helper()
	if dir == "" {
		return
	}

	// Create a file system from the directory
	fsys := os.DirFS(dir)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Add files from the directory file system to the tar archive
	err := tw.AddFS(fsys)
	require.NoError(t, err)
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
