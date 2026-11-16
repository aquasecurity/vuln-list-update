package ubuntu_test

import (
	"archive/zip"
	"compress/gzip"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/ubuntu"
)

func TestOSVUpdater_Update(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		archivePath string
		wantErr     string
	}{
		{
			// testdata/osv/advisories contains:
			// - UBUNTU-CVE-2026-21218: dotnet8 fixed in 24.04 with binary versions that differ
			//   from the source version, and dotnet6 unfixed in 22.04
			// - UBUNTU-CVE-2026-0861: glibc fixed in 24.04, 25.10 and Ubuntu:Pro:20.04:LTS
			// - UBUNTU-CVE-2026-100290: glibc unfixed in 24.04 and Ubuntu:Pro:20.04:LTS
			// - UBUNTU-CVE-2026-10154: dolibarr only in Ubuntu:Pro:16.04:LTS
			// - UBUNTU-CVE-2026-0002: openssl with two different fixed versions in 24.04,
			//   and libxml2 in 24.04 without binaries
			// - UBUNTU-CVE-2021-3345: withdrawn record for libgcrypt20 in 18.04 and 20.04
			// - UBUNTU-CVE-2024-26581: kernel source packages linux and linux-aws in 22.04
			// - USN-9091-1: linux-nvidia-tegra in 24.04
			//
			// testdata/osv/archive contains Sources indices of noble and jammy in the archive,
			// and of questing in old-releases. zlib and linux there have no OSV records.
			// The Binary field of glibc in noble-updates continues on the next line.
			name:        "happy path",
			path:        "/Ubuntu/all.zip",
			archivePath: "/archive",
		},
		{
			name:        "sad path, unable to download archive",
			path:        "/unknown.zip",
			archivePath: "/archive",
			wantErr:     "bad response code: 404",
		},
		{
			name:        "sad path, release is not in the Ubuntu archive",
			path:        "/Ubuntu/all.zip",
			archivePath: "/unknown",
			wantErr:     "jammy is not found",
		},
	}

	archive := buildArchive(t, filepath.Join("testdata", "osv", "advisories"))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/Ubuntu/all.zip", func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, archive)
			})
			mux.HandleFunc("/", serveUbuntuArchive(t, filepath.Join("testdata", "osv", "archive")))
			ts := httptest.NewServer(mux)
			defer ts.Close()

			testDir := t.TempDir()

			// The file must be removed, since the source no longer has it
			stale := filepath.Join(testDir, "ubuntu-osv", "24.04", "stale.json")
			require.NoError(t, os.MkdirAll(filepath.Dir(stale), 0o755))
			require.NoError(t, os.WriteFile(stale, []byte("{}"), 0o600))

			u := ubuntu.NewOSVUpdater(
				ubuntu.WithOSVURL(ts.URL+tt.path),
				ubuntu.WithArchiveURLs(ts.URL+tt.archivePath, ts.URL+"/old-releases"),
				ubuntu.WithOSVDir(testDir),
			)
			err := u.Update()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			goldenDir := filepath.Join("testdata", "osv", "golden")
			want := listFiles(t, goldenDir)
			require.ElementsMatch(t, want, listFiles(t, testDir))

			for _, rel := range want {
				wantJSON, err := os.ReadFile(filepath.Join(goldenDir, rel))
				require.NoError(t, err)
				gotJSON, err := os.ReadFile(filepath.Join(testDir, rel))
				require.NoError(t, err)
				assert.JSONEq(t, string(wantJSON), string(gotJSON), rel)
			}
		})
	}
}

// serveUbuntuArchive serves an Ubuntu archive from dir, where the first path element names the archive.
// A release exists if dir has its dists/<codename> directory. Sources.gz is gzipped from the Sources file,
// and it is empty if there is no such file.
func serveUbuntuArchive(t *testing.T, dir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		local := filepath.Join(dir, filepath.FromSlash(r.URL.Path))
		switch filepath.Base(local) {
		case "Release":
			if _, err := os.Stat(filepath.Dir(local)); err != nil {
				http.NotFound(w, r)
			}
		case "Sources.gz":
			b, err := os.ReadFile(strings.TrimSuffix(local, ".gz"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				require.NoError(t, err)
			}
			gw := gzip.NewWriter(w)
			_, err = gw.Write(b)
			require.NoError(t, err)
			require.NoError(t, gw.Close())
		default:
			http.NotFound(w, r)
		}
	}
}

// buildArchive packs the files of dir into a zip archive in the same flat layout as all.zip on osv.dev.
func buildArchive(t *testing.T, dir string) string {
	archive := filepath.Join(t.TempDir(), "all.zip")
	f, err := os.Create(archive)
	require.NoError(t, err)
	defer f.Close()

	zw := zip.NewWriter(f)
	require.NoError(t, zw.AddFS(os.DirFS(dir)))
	require.NoError(t, zw.Close())
	return archive
}

// listFiles returns paths of regular files under dir, relative to dir.
func listFiles(t *testing.T, dir string) []string {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		require.NoError(t, err)
		files = append(files, rel)
		return nil
	})
	require.NoError(t, err)
	return files
}
