package echo

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type expectedVuln struct {
	Package      string
	CVE          string
	FixedVersion string
}

func TestUpdater_Update(t *testing.T) {
	tests := []struct {
		name        string
		testFile    string
		wantErr     bool
		expected    []expectedVuln
	}{
		{
			name:     "valid response",
			testFile: "testdata/valid.json",
			expected: []expectedVuln{
				{
					Package:      "nginx",
					CVE:          "CVE-2023-44487",
					FixedVersion: "1.25.2",
				},
				{
					Package:      "python",
					CVE:          "CVE-2024-9287",
					FixedVersion: "3.9.21",
				},
				{
					Package:      "python",
					CVE:          "CVE-2009-2940",
					FixedVersion: "",
				},
				{
					Package:      "python", 
					CVE:          "CVE-2020-29396",
					FixedVersion: "",
				},
				{
					Package:      "python",
					CVE:          "CVE-2021-32052",
					FixedVersion: "",
				},
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
				WithFilePath(""),
			)

			err = updater.Update()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			// Validate each expected vulnerability
			for _, expected := range tt.expected {
				filePath := filepath.Join(tmpDir, echoDir, expected.Package+".json")
				fileContent, err := os.ReadFile(filePath)
				require.NoError(t, err)

				var vulnData map[string]struct {
					Severity     string `json:"severity,omitempty"`
					FixedVersion string `json:"fixed_version,omitempty"`
				}
				err = json.Unmarshal(fileContent, &vulnData)
				require.NoError(t, err)

				vuln, exists := vulnData[expected.CVE]
				require.True(t, exists, "CVE %s not found in %s", expected.CVE, expected.Package)
				
				assert.Equal(t, expected.FixedVersion, vuln.FixedVersion, "Package: %s, CVE: %s", expected.Package, expected.CVE)
			}
		})
	}
}
