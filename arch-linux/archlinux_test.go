package arch_linux

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func TestUpdate(t *testing.T) {
	testCases := []struct {
		name                   string
		inputJSONFile          string
		expectedOutputJSONFile string
		expectedError          string
		ArchLinuxServerUrl     string
	}{
		{
			name:                   "happy path",
			inputJSONFile:          "testdata/archlinux.json",
			expectedOutputJSONFile: "testdata/AVG-4.json",
		},
		{
			name:               "sad path, unreachable Arch Linux service",
			expectedError:      "failed to retrieve Arch Linux CVE details",
			ArchLinuxServerUrl: "http://foo/bar/baz",
		},
		{
			name:          "sad path, invalid json",
			inputJSONFile: "testdata/invalid.json",
			expectedError: "failed to retrieve Arch Linux CVE details",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var ArchLinuxURL string
			if tc.ArchLinuxServerUrl != "" {
				ArchLinuxURL = tc.ArchLinuxServerUrl
			} else {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					b, _ := os.ReadFile(tc.inputJSONFile)
					_, _ = io.WriteString(w, string(b))
				}))
				ArchLinuxURL = ts.URL
				defer ts.Close()
			}

			dir := t.TempDir()

			c := NewArchLinuxWithConfig(ArchLinuxURL, filepath.Join(dir), 0)
			err := c.Update()
			switch {
			case tc.expectedError != "":
				require.Error(t, err, tc.name)
			default:
				gotJSON, err := os.ReadFile(filepath.Join(dir, "AVG-4.json"))
				require.NoError(t, err, tc.name)

				wantJSON, _ := os.ReadFile(tc.expectedOutputJSONFile)
				assert.JSONEq(t, string(wantJSON), string(gotJSON), tc.name)
			}
		})
	}
}
