package fedora_test

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aquasecurity/vuln-list-update/fedora"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "update golden files")

func TestConfig_Update(t *testing.T) {
	testCases := []struct {
		name             string
		appFs            afero.Fs
		bzip2FileNames   map[string]string
		goldenFiles      map[string]string
		expectedErrorMsg string
	}{
		{
			name:  "positive test",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/updates/1": "testdata/FedoraUpdateIds1.json",
				"/updates/2": "testdata/FedoraUpdateIds2.json",
			},
			goldenFiles: map[string]string{
				"/tmp/fedora/2019/FEDORA-2019-210b0a6e4f.json":      "testdata/golden/FEDORA-2019-210b0a6e4f.json",
				"/tmp/fedora/2019/FEDORA-2019-5898f4f935.json":      "testdata/golden/FEDORA-2019-5898f4f935.json",
				"/tmp/fedora/2019/FEDORA-2019-72e5ac943a.json":      "testdata/golden/FEDORA-2019-72e5ac943a.json",
				"/tmp/fedora/2019/FEDORA-2019-9f9b38c8e5.json":      "testdata/golden/FEDORA-2019-9f9b38c8e5.json",
				"/tmp/fedora/2019/FEDORA-2019-adf618865f.json":      "testdata/golden/FEDORA-2019-adf618865f.json",
				"/tmp/fedora/2019/FEDORA-2019-caff41caf8.json":      "testdata/golden/FEDORA-2019-caff41caf8.json",
				"/tmp/fedora/2019/FEDORA-2019-f12cb1ddab.json":      "testdata/golden/FEDORA-2019-f12cb1ddab.json",
				"/tmp/fedora/2019/FEDORA-2019-f6ea699dbb.json":      "testdata/golden/FEDORA-2019-f6ea699dbb.json",
				"/tmp/fedora/2019/FEDORA-EPEL-2019-35adef43f8.json": "testdata/golden/FEDORA-EPEL-2019-35adef43f8.json",
				"/tmp/fedora/2019/FEDORA-EPEL-2019-360263f378.json": "testdata/golden/FEDORA-EPEL-2019-360263f378.json",
			},
		},
		{
			name:  "invalid filesystem write read only path",
			appFs: afero.NewReadOnlyFs(afero.NewOsFs()),
			bzip2FileNames: map[string]string{
				"/updates/1": "testdata/FedoraUpdateIds1.json",
				"/updates/2": "testdata/FedoraUpdateIds2.json",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to create dir: operation not permitted",
		},
		{
			name:  "invalid json file",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/updates/1": "testdata/FedoraUpdateIds1.json",
				"/updates/2": "testdata/invalid.json",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to unmarshal fedora advisories pagenations: unexpected end of JSON input",
		},
		{
			name:  "EOF file",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/updates/1": "testdata/FedoraUpdateIds1.json",
				"/updates/2": "testdata/EOF.json",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to unmarshal fedora advisories pagenations: unexpected end of JSON input",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				filePath, ok := tc.bzip2FileNames[r.URL.Path]
				if !ok {
					http.NotFound(w, r)
					return
				}
				b, err := ioutil.ReadFile(filePath)
				assert.NoError(t, err, tc.name)
				_, err = w.Write(b)
				assert.NoError(t, err, tc.name)
			}))
			defer ts.Close()
			url := ts.URL + "/updates/%d"
			c := fedora.Config{
				VulnListDir: "/tmp",
				URL:         url,
				AppFs:       tc.appFs,
				Retry:       0,
			}
			err := c.Update()
			switch {
			case tc.expectedErrorMsg != "":
				require.NotNil(t, err, tc.name)
				assert.Contains(t, err.Error(), tc.expectedErrorMsg, tc.name)
				return
			default:
				assert.NoError(t, err, tc.name)
			}

			fileCount := 0
			err = afero.Walk(c.AppFs, "/", func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				fileCount += 1

				actual, err := afero.ReadFile(c.AppFs, path)
				assert.NoError(t, err, tc.name)

				goldenPath, ok := tc.goldenFiles[path]
				if !ok {
					fmt.Println(path)
				}
				assert.True(t, ok, tc.name)

				if *update {
					err = ioutil.WriteFile(goldenPath, actual, 0666)
					assert.NoError(t, err, tc.name)
				}

				expected, err := ioutil.ReadFile(goldenPath)
				assert.NoError(t, err, tc.name)

				assert.Equal(t, expected, actual, tc.name)

				return nil
			})
			assert.Equal(t, len(tc.goldenFiles), fileCount, tc.name)
			assert.NoError(t, err, tc.name)
		})
	}
}
