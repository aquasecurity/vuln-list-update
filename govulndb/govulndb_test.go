package govulndb

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdate(t *testing.T) {
	testCases := []struct {
		name                   string
		mockIndexJsonFile      string
		mockvulnJsonFile       string
		expectedOutputJSONFile string
		expectedError          string
	}{
		{
			name:                   "happy path",
			mockIndexJsonFile:      "testdata/index.json",
			mockvulnJsonFile:       "testdata/github.com-dhowden-tag.json",
			expectedOutputJSONFile: "testdata/expected-GO-2021-0097.json",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "index.json"):
					repomd, _ := ioutil.ReadFile(tc.mockIndexJsonFile)
					_, _ = w.Write(repomd)
				case strings.Contains(r.URL.Path, "github.com/dhowden/tag.json"):
					buf, _ := ioutil.ReadFile(tc.mockvulnJsonFile)
					_, _ = w.Write(buf)
				default:
					assert.Fail(t, "bad URL requested: ", r.URL.Path, tc.name)
				}
			}))
			defer func() {
				ts.Close()
			}()

			dir, _ := ioutil.TempDir("", "Test-GoVulnDB-Update-*")
			defer func() {
				_ = os.RemoveAll(dir)
			}()

			c := NewGoVulnDBWithCustomConfig(ts.URL, filepath.Join(dir, "go"))
			err := c.Update()
			switch {
			case tc.expectedError != "":
				require.Error(t, err, tc.name)
			default:
				gotJSON, err := ioutil.ReadFile(filepath.Join(dir, "go", "github.com/dhowden/tag/GO-2021-0097.json"))
				require.NoError(t, err, tc.name)

				wantJSON, _ := ioutil.ReadFile(tc.expectedOutputJSONFile)
				assert.JSONEq(t, string(wantJSON), string(gotJSON), tc.name)
			}
		})
	}
}
