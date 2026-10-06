package oval

import (
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "update golden files")

func TestConfig_Update(t *testing.T) {
	testCases := []struct {
		name      string
		dir       string
		wantFiles int
		wantErr   string
	}{
		{
			name:      "happy path",
			dir:       "testdata/happy",
			wantFiles: 24,
		},
		{
			name:    "404",
			dir:     "testdata/missing-oval",
			wantErr: "failed to fetch Red Hat OVAL v2: failed to fetch URL: HTTP error. status code: 404, url:",
		},
		{
			name:    "invalid file format",
			dir:     "testdata/invalid-bzip2",
			wantErr: "failed to unmarshal Red Hat OVAL v2 XML: bzip2 data invalid: bad magic value",
		},
		{
			name:    "broken XML",
			dir:     "testdata/broken-xml",
			wantErr: "failed to unmarshal Red Hat OVAL v2 XML: XML syntax error on line 411: element",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.FileServer(http.Dir(tc.dir)))
			defer ts.Close()

			tmpDir := "/tmp" // It is a virtual filesystem of afero.
			appFs := afero.NewMemMapFs()
			c := Config{
				VulnListDir:  tmpDir,
				URLFormat:    ts.URL + "/%s",
				RepoToCpeURL: ts.URL + "/repository-to-cpe.json",
				AppFs:        appFs,
				Retry:        0,
			}

			err := c.Update()
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}

			require.NoError(t, err, tc.name)

			fileCount := 0
			root := tmpDir + "/oval"
			err = afero.Walk(appFs, root, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				} else if info.IsDir() {
					return nil
				}
				fileCount++

				got, err := afero.ReadFile(appFs, path)
				assert.NoError(t, err, tc.name)

				rel, err := filepath.Rel(root, path)
				require.NoError(t, err)

				rel = strings.ReplaceAll(rel, ":", "-")
				goldenPath := filepath.Join("testdata", "golden", rel)
				if *update {
					err = os.WriteFile(goldenPath, got, 0666)
					require.NoError(t, err, goldenPath)
				}
				want, err := os.ReadFile(goldenPath)
				assert.NoError(t, err, tc.name)

				assert.JSONEq(t, string(want), string(got), path)

				return nil
			})
			assert.NoError(t, err, tc.name)
			assert.Equal(t, tc.wantFiles, fileCount, tc.name)
		})
	}
}

func TestConfig_saveRHSAPerYear(t *testing.T) {
	testCases := []struct {
		name    string
		rhsaID  string
		wantErr error
	}{
		{
			name:   "happy path",
			rhsaID: "RHSA-2018:0094",
		},
		{
			name:    "sad path: invalid RHSA-ID format",
			rhsaID:  "foobarbaz",
			wantErr: errors.New("invalid RHSA-ID format"),
		},
	}

	for _, tc := range testCases {
		c := Config{
			AppFs: afero.NewMemMapFs(),
		}

		err := c.saveAdvisoryPerYear("/tmp", tc.rhsaID, Definition{})
		switch {
		case tc.wantErr != nil:
			assert.Equal(t, tc.wantErr.Error(), err.Error(), tc.name)
		default:
			assert.NoError(t, err, tc.name)
		}
	}
}
