package rootio_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/osv"
	"github.com/aquasecurity/vuln-list-update/rootio"
)

func Test_Update(t *testing.T) {
	const archivePath = "/external/osv/all.zip"

	tests := []struct {
		name      string
		path      string
		wantFiles []string
		wantErr   string
	}{
		{
			name: "happy path",
			wantFiles: []string{
				filepath.Join("curl", "CVE-2023-0001.json"),
				filepath.Join("openssl", "CVE-2023-0002.json"),
			},
		},
		{
			name:    "sad path, unable to download archive",
			path:    "/unknown.zip",
			wantErr: "bad response code: 404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != archivePath {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, filepath.Join("testdata", "all.zip"))
			}))
			defer ts.Close()

			testDir := t.TempDir()
			testURL := ts.URL + archivePath
			if tt.path != "" {
				testURL = ts.URL + tt.path
			}

			ecosystems := map[string]osv.Ecosystem{
				"Root": {
					Dir: "",
					URL: testURL,
				},
			}

			db := rootio.NewDatabase(
				rootio.WithDir(testDir),
				rootio.WithEcosystems(ecosystems),
			)

			err := db.Update()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			for _, wantFile := range tt.wantFiles {
				got, err := os.ReadFile(filepath.Join(testDir, wantFile))
				require.NoError(t, err)

				want, err := os.ReadFile(filepath.Join("testdata", "golden", wantFile))
				require.NoError(t, err)

				assert.JSONEq(t, string(want), string(got))
			}

			// Records with no affected packages must be skipped.
			_, err = os.Stat(filepath.Join(testDir, "CVE-2023-0003.json"))
			assert.True(t, os.IsNotExist(err), "record without affected packages should not be written")
		})
	}
}
