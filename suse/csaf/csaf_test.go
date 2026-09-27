package csaf_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/suse/csaf"
)

func createArchive(t *testing.T, dir string) []byte {
	t.Helper()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	require.NoError(t, tw.AddFS(os.DirFS(dir)))
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	return buf.Bytes()
}

func newTestServer(t *testing.T, archiveData []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write(archiveData)
		require.NoError(t, err)
	}))
}

func TestConfig_Update(t *testing.T) {
	testCases := []struct {
		name       string
		archiveDir string
		wantFiles  map[string]string
	}{
		{
			name:       "positive test",
			archiveDir: "testdata/csaf",
			wantFiles: map[string]string{
				"/tmp/csaf/suse/suse/2019/SUSE-SU-2019-0048-2.json":         "testdata/golden/SUSE-SU-2019-0048-2.json",
				"/tmp/csaf/suse/opensuse/2019/openSUSE-SU-2019-0003-1.json": "testdata/golden/openSUSE-SU-2019-0003-1.json",
			},
		},
		{
			name:       "broken JSON is skipped",
			archiveDir: "testdata/broken-csaf",
			wantFiles:  map[string]string{},
		},
		{
			name:       "invalid advisories are skipped",
			archiveDir: "testdata/invalid-csaf",
			wantFiles:  map[string]string{},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestServer(t, createArchive(t, tc.archiveDir))
			defer ts.Close()

			fs := afero.NewMemMapFs()
			c := csaf.Config{
				VulnListDir: "/tmp",
				URL:         ts.URL + "/csaf.tar.gz",
				AppFs:       fs,
			}
			require.NoError(t, c.Update())

			if len(tc.wantFiles) == 0 {
				_, err := fs.Stat(filepath.Join(c.VulnListDir, "csaf"))
				assert.Error(t, err)
				return
			}

			fileCount := 0
			err := afero.Walk(fs, c.VulnListDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				fileCount++

				goldenPath, ok := tc.wantFiles[path]
				require.True(t, ok, "unexpected output file: %s", path)

				actual, err := afero.ReadFile(fs, path)
				require.NoError(t, err)

				expected, err := os.ReadFile(goldenPath)
				require.NoError(t, err)
				if os.Getenv("UPDATE_GOLDEN") != "" {
					require.NoError(t, os.WriteFile(goldenPath, actual, 0o644))
					return nil
				}
				assert.JSONEq(t, string(expected), string(actual))

				return nil
			})
			require.NoError(t, err)
			assert.Equal(t, len(tc.wantFiles), fileCount)
		})
	}
}

func TestOsNameFromFilename(t *testing.T) {
	tests := map[string]struct {
		filename string
		wantOS   string
		wantOK   bool
	}{
		"suse":       {filename: "suse-su-2019_0048-2.json", wantOS: "suse", wantOK: true},
		"opensuse":   {filename: "opensuse-su-2019_0003-1.json", wantOS: "opensuse", wantOK: true},
		"sha256":     {filename: "suse-su-2019_0048-2.json.sha256", wantOS: "", wantOK: false},
		"unexpected": {filename: "LICENSE", wantOS: "", wantOK: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			gotOS, gotOK := csaf.OsNameFromFilename(tt.filename)
			assert.Equal(t, tt.wantOK, gotOK)
			assert.Equal(t, tt.wantOS, gotOS)
		})
	}
}
