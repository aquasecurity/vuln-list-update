package cvrfcve_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/suse/cvrfcve"
)

var update = flag.Bool("update", false, "update golden files")

const goldenDir = "testdata/golden"

// createArchive creates a tar.gz archive from the given directory.
// gzip is used instead of bzip2 because Go's compress/bzip2 package
// only provides a Reader. The production code detects the format by
// URL suffix and handles both .tar.bz2 and .tar.gz.
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
		name       string
		appFs      afero.Fs
		archiveDir string
		// wantGolden lists the golden file basenames expected to be produced
		// for this case (empty when wantErr is set). Each name is resolved
		// against testdata/golden/ and matched to a produced file by basename.
		wantGolden []string
		wantErr    string
	}{
		{
			name:       "positive test",
			appFs:      afero.NewMemMapFs(),
			archiveDir: "testdata/cvrfcve",
			wantGolden: []string{
				"CVE-1234-12345.json",
				"CVE-2014-6271.json",
			},
		},
		{
			name:       "broken XML",
			appFs:      afero.NewMemMapFs(),
			archiveDir: "testdata/broken-cvrfcve",
			wantErr:    "failed to decode SUSE CVE CVRF XML",
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

			c := cvrfcve.Config{
				VulnListDir: t.TempDir(),
				URL:         ts.URL + "/cvrf-cve.tar.gz",
				AppFs:       tc.appFs,
			}
			err := c.Update()
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr, tc.name)
				return
			}
			require.NoError(t, err, tc.name)

			// Collect everything the updater wrote, keyed by basename. Basenames
			// are unique because CVE IDs are unique across years.
			produced := map[string][]byte{}
			err = afero.Walk(c.AppFs, c.VulnListDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				data, err := afero.ReadFile(c.AppFs, path)
				if err != nil {
					return err
				}
				produced[filepath.Base(path)] = data
				return nil
			})
			require.NoError(t, err, tc.name)

			assert.Len(t, produced, len(tc.wantGolden), tc.name)
			for _, name := range tc.wantGolden {
				actual, ok := produced[name]
				require.True(t, ok, "%s: %s was not produced", tc.name, name)

				goldenPath := filepath.Join(goldenDir, name)
				if *update {
					require.NoError(t, os.WriteFile(goldenPath, actual, 0o644), tc.name)
				}
				expected, err := os.ReadFile(goldenPath)
				require.NoError(t, err, tc.name)

				assert.Equal(t, string(expected), string(actual), tc.name)
			}
		})
	}
}
