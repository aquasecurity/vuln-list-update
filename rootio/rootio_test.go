package rootio

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdater_Update(t *testing.T) {
	tests := []struct {
		name     string
		testFile string
		wantErr  bool
	}{
		{
			name:     "valid response",
			testFile: "testdata/valid.json",
		},
		{
			name:     "invalid JSON response",
			testFile: "testdata/invalid.json",
			wantErr:  true,
		},
		{
			name:     "requesting non-existent file",
			testFile: "testdata/non-existent.json",
			wantErr:  true,
		},
		{
			name:     "empty test file",
			testFile: "",
			wantErr:  true,
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
			)

			err := updater.Update()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			// Verify the directory structure and files were created correctly
			rootioDir := filepath.Join(tmpDir, rootioDir)
			assert.DirExists(t, rootioDir)

			// Check that the main CVE feed file was created
			feedFilePath := filepath.Join(rootioDir, "cve_feed.json")
			assert.FileExists(t, feedFilePath)

			// Verify the content matches the golden file
			expectedPath := "testdata/golden/cve_feed.json"
			if _, err := os.Stat(expectedPath); err == nil {
				actual, err := os.ReadFile(feedFilePath)
				require.NoError(t, err)

				expected, err := os.ReadFile(expectedPath)
				require.NoError(t, err)

				assert.JSONEq(t, string(expected), string(actual))
			}
		})
	}
}