package seal_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/seal"
)

func Test_Update(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantFiles []string
		wantErr   string
	}{
		{
			name: "happy path",
			wantFiles: []string{
				filepath.Join("seal-screen", "CVE-2025-46803.json"),
				filepath.Join("seal-glibc", "CVE-2023-6780.json"),
				filepath.Join("seal-rsync", "CVE-2020-14387.json"),
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
				if r.URL.Path != "/v1/osv/renamed/vulnerabilities.zip" {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, filepath.Join("testdata", "vulnerabilities.zip"))
			}))
			defer ts.Close()

			// build test settings
			testDir := t.TempDir()
			testURL := ts.URL + "/v1/osv/renamed/vulnerabilities.zip"
			if tt.path != "" {
				testURL = ts.URL + tt.path
			}

			c := seal.NewSeal(seal.WithURL(testURL), seal.WithDir(testDir))

			err := c.Update()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)

			for _, wantFile := range tt.wantFiles {
				got, err := os.ReadFile(filepath.Join(testDir, wantFile))
				require.NoError(t, err)

				want, err := os.ReadFile(filepath.Join("testdata", "golden", wantFile))
				require.NoError(t, err)

				assert.JSONEq(t, string(want), string(got))
			}
		})
	}
}
