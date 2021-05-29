package safetydb_test

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vulndb "github.com/aquasecurity/vuln-list-update/python/safetydb"
)

func TestUpdate(t *testing.T) {
	testCases := []struct {
		name                   string
		mocksafetyDBJsonFile   string
		expectedOutputJSONFile string
		expectedError          string
	}{
		{
			name:                   "happy path",
			mocksafetyDBJsonFile:   "testdata/insecure_full.json",
			expectedOutputJSONFile: "testdata/expected_pyup.io-25694.json",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				repomd, _ := ioutil.ReadFile(tc.mocksafetyDBJsonFile)
				_, _ = w.Write(repomd)

			}))
			defer func() {
				ts.Close()
			}()

			dir := t.TempDir()

			c := vulndb.NewVulnDB(vulndb.WithURL(ts.URL), vulndb.WithDir(filepath.Join(dir, "python/safety-db")))
			err := c.Update()
			if tc.expectedError != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), err)
				return
			}

			gotJSON, err := ioutil.ReadFile(filepath.Join(dir, "python/safety-db", "django/pyup.io-25694.json"))
			require.NoError(t, err, tc.name)

			wantJSON, err := ioutil.ReadFile(tc.expectedOutputJSONFile)
			require.NoError(t, err, tc.name)

			assert.JSONEq(t, string(wantJSON), string(gotJSON), tc.name)
		})
	}
}
