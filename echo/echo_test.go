package echo

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
		name          string
		testFile      string
		wantErr       bool
		expectedFiles map[string]string
	}{
		{
			name:     "valid response",
			testFile: "testdata/valid.json",
			expectedFiles: map[string]string{
				"nginx.json":  "testdata/golden/nginx.json",
				"python.json": "testdata/golden/python.json",
				"redis.json":  "testdata/golden/redis.json",
			},
		},
		{
			name:     "invalid JSON response",
			testFile: "testdata/invalid.json",
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

			tmpDir, err := os.MkdirTemp("", "echo-test")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			serverURL, _ := url.Parse(ts.URL)
			updater := NewUpdater(
				WithBaseURL(serverURL),
				WithVulnListDir(tmpDir),
			)

			err = updater.Update()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			for fileName, expectedPath := range tt.expectedFiles {
				filePath := filepath.Join(tmpDir, echoDir, fileName)
				actual, err := os.ReadFile(filePath)
				require.NoError(t, err)

				expected, err := os.ReadFile(expectedPath)
				require.NoError(t, err)

				assert.JSONEq(t, string(expected), string(actual))
			}
		})
	}
}
