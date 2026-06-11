package csaf_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
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

func TestConfig_Update(t *testing.T) {
	testCases := []struct {
		name        string
		appFs       afero.Fs
		archiveDir  string
		goldenFiles map[string]string
	}{
		{
			name:       "positive test",
			appFs:      afero.NewMemMapFs(),
			archiveDir: "testdata/csaf",
			goldenFiles: map[string]string{
				"/tmp/csaf/suse/suse/2019/SUSE-SU-2019-0048-2.json":         "testdata/golden/SUSE-SU-2019-0048-2.json",
				"/tmp/csaf/suse/opensuse/2019/openSUSE-SU-2019-0003-1.json": "testdata/golden/openSUSE-SU-2019-0003-1.json",
			},
		},
		{
			name:        "broken JSON is skipped",
			appFs:       afero.NewMemMapFs(),
			archiveDir:  "testdata/broken-csaf",
			goldenFiles: map[string]string{},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			archiveData := createArchive(t, tc.archiveDir)

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err := w.Write(archiveData)
				assert.NoError(t, err, tc.name)
			}))
			defer ts.Close()

			c := csaf.Config{
				VulnListDir: "/tmp",
				URL:         ts.URL + "/csaf.tar.gz",
				AppFs:       tc.appFs,
			}
			err := c.Update()
			require.NoError(t, err, tc.name)

			fileCount := 0
			err = afero.Walk(c.AppFs, "/", func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				fileCount++

				actual, err := afero.ReadFile(c.AppFs, path)
				require.NoError(t, err, tc.name)

				goldenPath, ok := tc.goldenFiles[path]
				require.True(t, ok, "unexpected output file: %s", path)
				expected, err := os.ReadFile(goldenPath)
				require.NoError(t, err, tc.name)

				assert.JSONEq(t, string(expected), string(actual), tc.name)

				return nil
			})
			require.NoError(t, err, tc.name)
			assert.Equal(t, len(tc.goldenFiles), fileCount, tc.name)
		})
	}
}
