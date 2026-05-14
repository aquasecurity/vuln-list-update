package echo_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/echo"
	"github.com/aquasecurity/vuln-list-update/osv"
)

func TestOSVUpdater_Update(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantFiles []string
		wantErr   string
	}{
		{
			name: "happy path",
			wantFiles: []string{
				filepath.Join("echo-osv", "openssh", "ECHO-003f-2632-599c.json"),
				filepath.Join("echo-osv", "pip", "ECHO-7db2-03aa-5591.json"),
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
				if r.URL.Path != "/osv/all.zip" {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, filepath.Join("testdata", "osv-all.zip"))
			}))
			defer ts.Close()

			testDir := t.TempDir()
			testURL := ts.URL + "/osv/all.zip"
			if tt.path != "" {
				testURL = ts.URL + tt.path
			}

			ecosystems := map[string]osv.Ecosystem{
				"echo": {
					Dir: "echo-osv",
					URL: testURL,
				},
			}

			db := echo.NewOSVUpdater(echo.WithOSVDir(testDir), echo.WithOSVEcosystems(ecosystems))

			err := db.Update()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)

			for _, wantFile := range tt.wantFiles {
				got, err := os.ReadFile(filepath.Join(testDir, wantFile))
				require.NoError(t, err)

				want, err := os.ReadFile(filepath.Join("testdata", "osv-golden", wantFile))
				require.NoError(t, err)

				assert.JSONEq(t, string(want), string(got))
			}
		})
	}
}
