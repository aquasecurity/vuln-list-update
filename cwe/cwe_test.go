package cwe

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdate(t *testing.T) {
	testCases := []struct {
		name                   string
		inputZipFile           string
		expectedOuptutXMLFile  string
		expectedOutputJSONFile string
		expectedError          string
		cweServerUrl           string
	}{
		{
			name:                   "happy path",
			inputZipFile:           "goldens/good-small-cwe.xml.zip",
			expectedOuptutXMLFile:  "goldens/good-small-cwe.xml",
			expectedOutputJSONFile: "goldens/good-small-cwe.json",
		},
		{
			name:          "sad path, corrupt xml file in zip",
			inputZipFile:  "goldens/corrupt.xml.zip",
			expectedError: "XML syntax error",
		},
		{
			name:          "sad path, invalid zip file",
			inputZipFile:  "goldens/bad.xml.zip",
			expectedError: "not a valid zip file",
		},
		{
			name:          "sad path, too many files in archive",
			inputZipFile:  "goldens/toomanyfiles.xml.zip",
			expectedError: "too many files in archive",
		},
		{
			name:          "sad path, unreachable CWE service",
			expectedError: "failed to fetch cwe data",
			cweServerUrl:  "http://foo/bar/baz",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var cweURL string
			if tc.cweServerUrl != "" {
				cweURL = tc.cweServerUrl
			} else {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					b, _ := os.ReadFile(tc.inputZipFile)
					_, _ = w.Write(b)
				}))
				cweURL = ts.URL
				defer func() {
					ts.Close()
				}()
			}

			dir := t.TempDir()
			c := NewCWEWithConfig(cweURL, filepath.Join(dir), 0)
			err := c.Update()
			switch {
			case tc.expectedError != "":
				require.Error(t, err, tc.name)
			default:
				// CWE-209.json is one file within good-small-cwe.xml.zip
				gotJSON, err := os.ReadFile(filepath.Join(dir, "CWE-209.json"))
				require.NoError(t, err, tc.name)

				wantJSON, _ := os.ReadFile(tc.expectedOutputJSONFile)
				assert.JSONEq(t, string(wantJSON), string(gotJSON), tc.name)
			}
		})
	}
}
