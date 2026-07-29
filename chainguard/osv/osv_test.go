package osv_test

import (
	"archive/tar"
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

	chainguardosv "github.com/aquasecurity/vuln-list-update/chainguard/osv"
)

var update = flag.Bool("update", false, "update golden files")

// tarball builds a gzipped tar of every file in dir, mirroring the layout of
// https://packages.cgr.dev/chainguard/v3/osv/chainguard-osv.tar.gz.
func tarball(t *testing.T, dir string) []byte {
	t.Helper()

	f, err := os.CreateTemp(t.TempDir(), "feed-*.tar.gz")
	require.NoError(t, err)
	defer f.Close()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, entry := range entries {
		b, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		require.NoError(t, err)
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:     entry.Name(),
			Typeflag: tar.TypeReg,
			Mode:     0644,
			Size:     int64(len(b)),
		}))
		_, err = tw.Write(b)
		require.NoError(t, err)
	}
	// A directory entry, which must be ignored rather than parsed.
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     "nested/",
		Typeflag: tar.TypeDir,
		Mode:     0755,
	}))

	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	b, err := os.ReadFile(f.Name())
	require.NoError(t, err)
	return b
}

func TestUpdater_Update(t *testing.T) {
	tests := []struct {
		name        string
		feedDir     string
		statusCode  int
		body        []byte
		goldenFiles map[string]string
		wantErr     string
	}{
		{
			name:    "happy path",
			feedDir: "testdata/feed",
			goldenFiles: map[string]string{
				"/tmp/chainguard/v3/chainguard/haproxy-2.2.json": "testdata/golden/chainguard/haproxy-2.2.json",
				"/tmp/chainguard/v3/chainguard/curl.json":        "testdata/golden/chainguard/curl.json",
				"/tmp/chainguard/v3/wolfi/haproxy-2.2.json":      "testdata/golden/wolfi/haproxy-2.2.json",
			},
		},
		{
			name:       "404",
			statusCode: http.StatusNotFound,
			wantErr:    "status code: 404",
		},
		{
			name:       "not gzipped",
			statusCode: http.StatusOK,
			body:       []byte("<html>not a tarball</html>"),
			wantErr:    "gzip reader error",
		},
		{
			name:       "no advisory records",
			feedDir:    "testdata/empty",
			statusCode: http.StatusOK,
			wantErr:    "no advisory records found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			switch {
			case tt.body != nil:
				body = tt.body
			case tt.feedDir != "":
				require.NoError(t, os.MkdirAll(tt.feedDir, 0755))
				body = tarball(t, tt.feedDir)
			}

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.statusCode != 0 && tt.statusCode != http.StatusOK {
					w.WriteHeader(tt.statusCode)
					return
				}
				_, _ = w.Write(body)
			}))
			defer ts.Close()

			appFs := afero.NewMemMapFs()
			u := chainguardosv.NewUpdater(
				chainguardosv.WithVulnListDir("/tmp"),
				chainguardosv.WithTarballURL(ts.URL),
				chainguardosv.WithRetry(0),
				chainguardosv.WithAppFs(appFs),
			)

			err := u.Update()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)

			fileCount := 0
			err = afero.Walk(appFs, "/", func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				fileCount++

				actual, err := afero.ReadFile(appFs, path)
				require.NoError(t, err, path)

				goldenPath, ok := tt.goldenFiles[path]
				require.True(t, ok, "unexpected output file %s", path)
				if *update {
					require.NoError(t, os.WriteFile(goldenPath, actual, 0600), goldenPath)
				}
				expected, err := os.ReadFile(goldenPath)
				require.NoError(t, err, goldenPath)
				assert.JSONEq(t, string(expected), string(actual), path)
				return nil
			})
			require.NoError(t, err)
			assert.Equal(t, len(tt.goldenFiles), fileCount)
		})
	}
}

// TestUpdater_Update_replacesPreviousRun checks that advisories removed from the
// feed do not linger in vuln-list.
func TestUpdater_Update_replacesPreviousRun(t *testing.T) {
	appFs := afero.NewMemMapFs()
	stale := "/tmp/chainguard/v3/chainguard/withdrawn-package.json"
	require.NoError(t, afero.WriteFile(appFs, stale, []byte(`{"name":"withdrawn-package"}`), 0644))

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(tarball(t, "testdata/feed"))
	}))
	defer ts.Close()

	u := chainguardosv.NewUpdater(
		chainguardosv.WithVulnListDir("/tmp"),
		chainguardosv.WithTarballURL(ts.URL),
		chainguardosv.WithRetry(0),
		chainguardosv.WithAppFs(appFs),
	)
	require.NoError(t, u.Update())

	exists, err := afero.Exists(appFs, stale)
	require.NoError(t, err)
	assert.False(t, exists, "stale advisory file should have been removed")
}

func TestUpdater_Update_retries(t *testing.T) {
	var calls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(tarball(t, "testdata/feed"))
	}))
	defer ts.Close()

	u := chainguardosv.NewUpdater(
		chainguardosv.WithVulnListDir("/tmp"),
		chainguardosv.WithTarballURL(ts.URL),
		chainguardosv.WithRetry(2),
		chainguardosv.WithAppFs(afero.NewMemMapFs()),
	)
	require.NoError(t, u.Update())
	assert.Equal(t, 3, calls)
}
