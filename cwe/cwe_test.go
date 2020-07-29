package cwe

import (
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpdate(t *testing.T) {
	testCases := []struct {
		name           string
		inputZipFile   string
		expectedOuptut string
		expectedError  string
		cweServerUrl   string
	}{
		{
			name:         "happy path",
			inputZipFile: "goldens/good.zip",
			expectedOuptut: `<message>
<body>foo bar baz</body>
</message>
`,
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
				b, err := ioutil.ReadFile(filepath.Join(dir, "cwe.xml"))
				assert.NoError(t, err, tc.name)
				assert.Equal(t, tc.expectedOuptut, string(b), tc.name)
			}
		})
	}
}
