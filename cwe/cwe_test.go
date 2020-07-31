package cwe

import (
	"io"
	"io/ioutil"
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
					b, _ := ioutil.ReadFile(tc.inputZipFile)
					_, _ = io.WriteString(w, string(b))
				}))
				cweURL = ts.URL
				defer func() {
					ts.Close()
				}()
			}

			dir, _ := ioutil.TempDir("", "TestUpdate-*")
			defer func() {
				_ = os.RemoveAll(dir)
			}()

			c := NewCWEWithConfig(cweURL, filepath.Join(dir), 0)
			err := c.Update()
			switch {
			case tc.expectedError != "":
				assert.Contains(t, err.Error(), tc.expectedError, tc.name)
			default:
				gotXML, err := ioutil.ReadFile(filepath.Join(dir, "cwe.xml"))
				require.NoError(t, err, tc.name)

				wantXML, _ := ioutil.ReadFile(tc.expectedOuptutXMLFile)
				assert.Equal(t, wantXML, gotXML, tc.name)

				gotJSON, err := ioutil.ReadFile(filepath.Join(dir, "cwe.json"))
				require.NoError(t, err, tc.name)

				wantJSON, _ := ioutil.ReadFile(tc.expectedOutputJSONFile)
				assert.JSONEq(t, string(wantJSON), string(gotJSON), tc.name)
			}
		})
	}
}
