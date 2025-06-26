package rootio

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "update golden files")

func TestUpdater_Update(t *testing.T) {
	tests := []struct {
		name     string
		testFile string
		wantErr  string
	}{
		{
			name:     "valid response",
			testFile: "testdata/valid.json",
		},
		{
			name:     "invalid JSON response",
			testFile: "testdata/invalid.json",
			wantErr:  "failed to parse Root.io CVE feed JSON",
		},
		{
			name:     "requesting non-existent file",
			testFile: "testdata/non-existent.json",
			wantErr:  "status code: 404",
		},
		{
			name:    "empty test file",
			wantErr: "status code: 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.testFile != "" {
					http.ServeFile(w, r, tt.testFile)
				} else {
					w.WriteHeader(http.StatusInternalServerError)
				}
			}))
			defer ts.Close()

			tmpDir := t.TempDir()

			serverURL, _ := url.Parse(ts.URL)
			updater := NewUpdater(
				WithBaseURL(serverURL),
				WithVulnListDir(tmpDir),
				WithRetry(0),
			)

			err := updater.Update()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)

			actual, err := os.ReadFile(filepath.Join(tmpDir, rootioDir, "cve_feed.json"))
			require.NoError(t, err)

			wantFile := filepath.Join("testdata", "happy", "cve_feed.json")
			if *update {
				err = os.WriteFile(wantFile, actual, 0666)
				require.NoError(t, err, wantFile)
			}

			expected, err := os.ReadFile(wantFile)
			require.NoError(t, err)

			assert.JSONEq(t, string(expected), string(actual))
		})
	}
}
