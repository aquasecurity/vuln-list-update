package rootio

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdater_Update(t *testing.T) {
	tests := []struct {
		name    string
		files   map[string]string // Map of URL path to test file
		wantErr string
	}{
		{
			name: "happy path",
			files: map[string]string{
				"external/cve_feed": "testdata/happy/rootio/cve_feed.json",
				"external/app_feed": "testdata/happy/rootio/app/cve_feed.json",
			},
		},
		{
			name: "sad path. Invalid OS JSON response",
			files: map[string]string{
				"external/cve_feed": "testdata/sad/invalid.json",
				"external/app_feed": "testdata/happy/rootio/app/cve_feed.json",
			},
			wantErr: "failed to parse Root.io feed JSON",
		},
		{
			name: "sad path. Invalid app JSON response",
			files: map[string]string{
				"external/cve_feed": "testdata/happy/rootio/cve_feed.json",
				"external/app_feed": "testdata/sad/invalid.json",
			},
			wantErr: "failed to parse Root.io feed JSON",
		},
		{
			name: "sad path. Feed not found",
			files: map[string]string{
				"external/cve_feed": "testdata/non-existent.json",
				"external/app_feed": "testdata/non-existent.json",
			},
			wantErr: "status code: 404",
		},
		{
			name:    "sad path. erver error",
			wantErr: "status code: 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := strings.TrimPrefix(r.URL.Path, "/")

				if len(tt.files) == 0 {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				if tf, ok := tt.files[path]; ok {
					if tf == "" {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					http.ServeFile(w, r, tf)
					return
				}
				http.NotFound(w, r)
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

			err = filepath.Walk(tmpDir, func(path string, info os.FileInfo, errfp error) error {
				if info.IsDir() {
					return nil
				}
				filename, err := filepath.Rel(tmpDir, path)
				if err != nil {
					return err
				}
				golden := filepath.Join("testdata", "happy", filename)

				want, err := os.ReadFile(golden)
				require.NoError(t, err, "failed to open the golden file")

				got, err := os.ReadFile(path)
				require.NoError(t, err, "failed to open the result file")
				assert.JSONEq(t, string(want), string(got))

				fmt.Println(string(got))

				return nil
			})
			assert.NoError(t, err)
		})
	}
}
