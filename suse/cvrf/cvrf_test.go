package cvrf_test

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/suse/cvrf"
)

var update = flag.Bool("update", false, "update golden files")

func TestConfig_Update(t *testing.T) {
	testCases := []struct {
		name             string
		appFs            afero.Fs
		xmlFileNames     map[string]string
		goldenFiles      map[string]string
		expectedErrorMsg string
	}{
		{
			name:  "positive test sles",
			appFs: afero.NewMemMapFs(),
			xmlFileNames: map[string]string{
				"/pub/projects/security/cvrf/":                                 "testdata/cvrf-list.html",
				"/pub/projects/security/cvrf/cvrf-suse-su-2018-1784-1.xml":     "testdata/cvrf-suse-su-2018-1784-1.xml",
				"/pub/projects/security/cvrf/cvrf-suse-su-2019-14018-1.xml":    "testdata/cvrf-suse-su-2019-14018-1.xml",
				"/pub/projects/security/cvrf/cvrf-suse-su-2019-1608-1.xml":     "testdata/cvrf-suse-su-2019-1608-1.xml",
				"/pub/projects/security/cvrf/cvrf-suse-su-2019-3294-1.xml":     "testdata/cvrf-suse-su-2019-3294-1.xml",
				"/pub/projects/security/cvrf/cvrf-suse-su-2019-3295-1.xml":     "testdata/cvrf-suse-su-2019-3295-1.xml",
				"/pub/projects/security/cvrf/cvrf-opensuse-su-2015-0225-1.xml": "testdata/cvrf-opensuse-su-2015-0225-1.xml",
				"/pub/projects/security/cvrf/cvrf-opensuse-su-2015-0798-1.xml": "testdata/cvrf-opensuse-su-2015-0798-1.xml",
				"/pub/projects/security/cvrf/cvrf-opensuse-su-2015-1289-1.xml": "testdata/cvrf-opensuse-su-2015-1289-1.xml",
				"/pub/projects/security/cvrf/cvrf-opensuse-su-2016-3233-1.xml": "testdata/cvrf-opensuse-su-2016-3233-1.xml",
				"/pub/projects/security/cvrf/cvrf-opensuse-su-2018-1633-1.xml": "testdata/cvrf-opensuse-su-2018-1633-1.xml",

				// include invalid UTF-8 characters
				"/pub/projects/security/cvrf/cvrf-opensuse-su-2016-0874-1.xml": "testdata/cvrf-opensuse-su-2016-0874-1.xml",
			},
			goldenFiles: map[string]string{
				"/tmp/cvrf/suse/suse/2018/SUSE-SU-2018-1784-1.json":         "testdata/golden/SUSE-SU-2018-1784-1.json",
				"/tmp/cvrf/suse/suse/2019/SUSE-SU-2019-14018-1.json":        "testdata/golden/SUSE-SU-2019-14018-1.json",
				"/tmp/cvrf/suse/suse/2019/SUSE-SU-2019-1608-1.json":         "testdata/golden/SUSE-SU-2019-1608-1.json",
				"/tmp/cvrf/suse/suse/2019/SUSE-SU-2019-3294-1.json":         "testdata/golden/SUSE-SU-2019-3294-1.json",
				"/tmp/cvrf/suse/suse/2019/SUSE-SU-2019-3295-1.json":         "testdata/golden/SUSE-SU-2019-3295-1.json",
				"/tmp/cvrf/suse/opensuse/2015/openSUSE-SU-2015-0225-1.json": "testdata/golden/openSUSE-SU-2015-0225-1.json",
				"/tmp/cvrf/suse/opensuse/2015/openSUSE-SU-2015-0798-1.json": "testdata/golden/openSUSE-SU-2015-0798-1.json",
				"/tmp/cvrf/suse/opensuse/2015/openSUSE-SU-2015-1289-1.json": "testdata/golden/openSUSE-SU-2015-1289-1.json",
				"/tmp/cvrf/suse/opensuse/2016/openSUSE-SU-2016-3233-1.json": "testdata/golden/openSUSE-SU-2016-3233-1.json",
				"/tmp/cvrf/suse/opensuse/2018/openSUSE-SU-2018-1633-1.json": "testdata/golden/openSUSE-SU-2018-1633-1.json",
				"/tmp/cvrf/suse/opensuse/2016/openSUSE-SU-2016-0874-1.json": "testdata/golden/openSUSE-SU-2016-0874-1.json",
			},
		},
		{
			name:  "invalid filesystem write read only path",
			appFs: afero.NewReadOnlyFs(afero.NewOsFs()),
			xmlFileNames: map[string]string{
				"/pub/projects/security/cvrf/":                             "testdata/invalid-cvrf-list.html",
				"/pub/projects/security/cvrf/cvrf-suse-su-2018-1784-1.xml": "testdata/golden/SUSE-SU-2018-1784-1.json",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed Update CVRF: failed to decode SUSE XML: EOF",
		},
		{
			name:  "empty file format",
			appFs: afero.NewMemMapFs(),
			xmlFileNames: map[string]string{
				"/pub/projects/security/cvrf/":                             "testdata/invalid-cvrf-list.html",
				"/pub/projects/security/cvrf/cvrf-suse-su-2018-1784-1.xml": "testdata/EOF.txt",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "",
		},
		{
			name:  "invalid file format",
			appFs: afero.NewMemMapFs(),
			xmlFileNames: map[string]string{
				"/pub/projects/security/cvrf/":                             "testdata/invalid-cvrf-list.html",
				"/pub/projects/security/cvrf/cvrf-suse-su-2018-1784-1.xml": "testdata/invalid.txt",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed Update CVRF: failed to decode SUSE XML: EOF",
		},
		{
			name:  "broken XML",
			appFs: afero.NewMemMapFs(),
			xmlFileNames: map[string]string{
				"/pub/projects/security/cvrf/":                             "testdata/invalid-cvrf-list.html",
				"/pub/projects/security/cvrf/cvrf-suse-su-2018-1784-1.xml": "testdata/broken-cvrf-data.xml",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed Update CVRF: failed to decode SUSE XML: XML syntax error on line 186: unexpected EOF",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				filePath, ok := tc.xmlFileNames[r.URL.Path]
				if !ok {
					http.NotFound(w, r)
					return
				}
				b, err := os.ReadFile(filePath)
				assert.NoError(t, err, tc.name)
				_, err = w.Write(b)
				assert.NoError(t, err, tc.name)
			}))
			defer ts.Close()
			url := ts.URL + "/pub/projects/security/cvrf/"
			c := cvrf.Config{
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
				require.NoError(t, err, tc.name)

				goldenPath, ok := tc.goldenFiles[path]
				assert.True(t, ok, tc.name)
				if *update {
					err = os.WriteFile(goldenPath, actual, 0666)
					assert.NoError(t, err, tc.name)
				}
				expected, err := os.ReadFile(goldenPath)
				assert.NoError(t, err, tc.name)

				assert.Equal(t, string(expected), string(actual), tc.name)

				return nil
			})
			assert.NoError(t, err, tc.name)
			assert.Equal(t, len(tc.goldenFiles), fileCount, tc.name)
		})
	}

}
