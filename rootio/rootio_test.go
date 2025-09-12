package rootio

import (
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
		name        string
		osTestFile  string
		appTestFile string
		wantErr     string
	}{
		{
			name:        "valid response",
			osTestFile:  "testdata/os_feed.json",
			appTestFile: "testdata/app_feed.json",
		},
		{
			name:        "invalid OS JSON response",
			osTestFile:  "testdata/invalid.json",
			appTestFile: "testdata/app_feed.json",
			wantErr:     "failed to parse Root.io OS package feed JSON",
		},
		{
			name:        "invalid app JSON response",
			osTestFile:  "testdata/os_feed.json",
			appTestFile: "testdata/invalid.json",
			wantErr:     "failed to parse Root.io application package feed JSON",
		},
		{
			name:        "OS feed not found",
			osTestFile:  "testdata/non-existent.json",
			appTestFile: "testdata/app_feed.json",
			wantErr:     "status code: 404",
		},
		{
			name:    "server error",
			wantErr: "status code: 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := strings.TrimPrefix(r.URL.Path, "/")

				if tt.osTestFile == "" && tt.appTestFile == "" {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				switch path {
				case "external/os_feed":
					if tt.osTestFile != "" {
						http.ServeFile(w, r, tt.osTestFile)
					} else {
						w.WriteHeader(http.StatusInternalServerError)
					}
				case "external/app_feed":
					if tt.appTestFile != "" {
						http.ServeFile(w, r, tt.appTestFile)
					} else {
						w.WriteHeader(http.StatusInternalServerError)
					}
				default:
					http.NotFound(w, r)
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

			// Verify OS feed exists and is valid
			osActual, err := os.ReadFile(filepath.Join(tmpDir, rootioDir, "os_feed.json"))
			require.NoError(t, err)

			osExpected, err := os.ReadFile(tt.osTestFile)
			require.NoError(t, err)
			assert.JSONEq(t, string(osExpected), string(osActual))

			// Verify app feed exists and is valid
			appActual, err := os.ReadFile(filepath.Join(tmpDir, rootioDir, "app_feed.json"))
			require.NoError(t, err)

			appExpected, err := os.ReadFile(tt.appTestFile)
			require.NoError(t, err)
			assert.JSONEq(t, string(appExpected), string(appActual))
		})
	}
}

func TestUpdater_UpdateWithSeparateFeeds(t *testing.T) {
	tests := []struct {
		name        string
		osTestFile  string
		appTestFile string
		wantErr     string
	}{
		{
			name:        "separate OS and app feeds",
			osTestFile:  "testdata/os_feed.json",
			appTestFile: "testdata/app_feed.json",
		},
		{
			name:        "OS feed with empty app feed",
			osTestFile:  "testdata/os_feed.json",
			appTestFile: "testdata/valid.json", // Empty/OS-only feed used as app feed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := strings.TrimPrefix(r.URL.Path, "/")

				switch path {
				case "external/os_feed":
					http.ServeFile(w, r, tt.osTestFile)
				case "external/app_feed":
					http.ServeFile(w, r, tt.appTestFile)
				default:
					http.NotFound(w, r)
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

			// Verify OS feed exists and contains expected data
			osFeedPath := filepath.Join(tmpDir, rootioDir, "os_feed.json")
			assert.FileExists(t, osFeedPath)

			osActual, err := os.ReadFile(osFeedPath)
			require.NoError(t, err)

			osExpected, err := os.ReadFile(tt.osTestFile)
			require.NoError(t, err)
			assert.JSONEq(t, string(osExpected), string(osActual))

			// Verify app feed exists and contains expected data
			appFeedPath := filepath.Join(tmpDir, rootioDir, "app_feed.json")
			assert.FileExists(t, appFeedPath)

			appActual, err := os.ReadFile(appFeedPath)
			require.NoError(t, err)

			appExpected, err := os.ReadFile(tt.appTestFile)
			require.NoError(t, err)
			assert.JSONEq(t, string(appExpected), string(appActual))
		})
	}
}
