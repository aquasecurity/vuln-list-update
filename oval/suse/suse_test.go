package suse_test

import (
	"flag"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aquasecurity/vuln-list-update/oval/suse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/spf13/afero"
)

var update = flag.Bool("update", false, "update golden files")

func TestConfig_Update(t *testing.T) {
	testCases := []struct {
		name             string
		appFs            afero.Fs
		xmlFileNames     map[string]string
		goldenFiles      map[string]string
		expectedErrorMsg string
		suseOSes         map[string][]string
	}{
		{
			name:  "positive test opensuse.leap",
			appFs: afero.NewMemMapFs(),
			xmlFileNames: map[string]string{
				"/pub/projects/security/oval/opensuse.leap.15.0.xml":               "testdata/opensuse.leap.15.0.xml",
				"/pub/projects/security/oval/opensuse.leap.15.1.xml":               "testdata/opensuse.leap.15.1.xml",
				"/pub/projects/security/oval/opensuse.leap.42.3.xml":               "testdata/opensuse.leap.42.3.xml",
				"/pub/projects/security/oval/suse.linux.enterprise.server.10.xml":  "testdata/suse.linux.enterprise.server.10.xml",
				"/pub/projects/security/oval/suse.linux.enterprise.server.11.xml":  "testdata/suse.linux.enterprise.server.11.xml",
				"/pub/projects/security/oval/suse.linux.enterprise.server.12.xml":  "testdata/suse.linux.enterprise.server.12.xml",
				"/pub/projects/security/oval/suse.linux.enterprise.server.15.xml":  "testdata/suse.linux.enterprise.server.15.xml",
				"/pub/projects/security/oval/suse.linux.enterprise.12.xml":         "testdata/suse.linux.enterprise.12.xml",
				"/pub/projects/security/oval/suse.linux.enterprise.15.xml":         "testdata/suse.linux.enterprise.15.xml",
				"/pub/projects/security/oval/suse.linux.enterprise.desktop.10.xml": "testdata/suse.linux.enterprise.desktop.10.xml",
				"/pub/projects/security/oval/suse.linux.enterprise.desktop.11.xml": "testdata/suse.linux.enterprise.desktop.11.xml",
				"/pub/projects/security/oval/suse.linux.enterprise.desktop.12.xml": "testdata/suse.linux.enterprise.desktop.12.xml",
				"/pub/projects/security/oval/suse.linux.enterprise.desktop.15.xml": "testdata/suse.linux.enterprise.desktop.15.xml",
			},
			goldenFiles: map[string]string{
				"/tmp/oval/suse/opensuse.leap/15.0/2019/CVE-2019-9937.json":               "testdata/golden/CVE-2019-9937.json",
				"/tmp/oval/suse/opensuse.leap/15.1/2018/CVE-2018-0734.json":               "testdata/golden/CVE-2018-0734.json",
				"/tmp/oval/suse/opensuse.leap/42.3/2015/CVE-2015-6564.json":               "testdata/golden/CVE-2015-6564.json",
				"/tmp/oval/suse/suse.linux.enterprise.server/10/2005/CVE-2005-1261.json":  "testdata/golden/CVE-2005-1261.json",
				"/tmp/oval/suse/suse.linux.enterprise.server/11/2013/CVE-2013-5889.json":  "testdata/golden/CVE-2013-5889.json",
				"/tmp/oval/suse/suse.linux.enterprise.server/12/2014/CVE-2014-0016.json":  "testdata/golden/CVE-2014-0016.json",
				"/tmp/oval/suse/suse.linux.enterprise.server/15/2018/CVE-2018-0202.json":  "testdata/golden/CVE-2018-0202.json",
				"/tmp/oval/suse/suse.linux.enterprise/12/2017/CVE-2017-0358.json":         "testdata/golden/CVE-2017-0358.json",
				"/tmp/oval/suse/suse.linux.enterprise/15/2018/CVE-2018-0360.json":         "testdata/golden/CVE-2018-0360.json",
				"/tmp/oval/suse/suse.linux.enterprise.desktop/10/2002/CVE-2002-2443.json": "testdata/golden/CVE-2002-2443.json",
				"/tmp/oval/suse/suse.linux.enterprise.desktop/10/2004/CVE-2004-0687.json": "testdata/golden/CVE-2004-0687.json",
				"/tmp/oval/suse/suse.linux.enterprise.desktop/11/2016/CVE-2016-2851.json": "testdata/golden/CVE-2016-2851.json",
				"/tmp/oval/suse/suse.linux.enterprise.desktop/12/2019/CVE-2019-8689.json": "testdata/golden/CVE-2019-8689.json",
			},
			suseOSes: map[string][]string{},
		},
		{
			name:  "invalid filesystem write read only path",
			appFs: afero.NewReadOnlyFs(afero.NewOsFs()),
			xmlFileNames: map[string]string{
				"/pub/projects/security/oval/opensuse.leap.15.0.xml": "testdata/opensuse.leap.15.0.xml",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed Update OVAL: failed to save CVE OVAL: operation not permitted",
			suseOSes:         map[string][]string{suse.OpenSUSELeap: {"15.0"}},
		},
		{
			name:  "empty file format",
			appFs: afero.NewMemMapFs(),
			xmlFileNames: map[string]string{
				"/pub/projects/security/oval/opensuse.leap.15.0.xml": "testdata/EOF.txt",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed Update OVAL: failed to decode SUSE XML: EOF",
			suseOSes:         map[string][]string{suse.OpenSUSELeap: {"15.0"}},
		},
		{
			name:             "404",
			appFs:            afero.NewMemMapFs(),
			xmlFileNames:     map[string]string{},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "404",
			suseOSes:         map[string][]string{},
		},
		{
			name:  "invalid file format",
			appFs: afero.NewMemMapFs(),
			xmlFileNames: map[string]string{
				"/pub/projects/security/oval/opensuse.leap.15.0.xml": "testdata/invalid.txt",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed Update OVAL: failed to decode SUSE XML: EOF",
			suseOSes:         map[string][]string{suse.OpenSUSELeap: {"15.0"}},
		},
		{
			name:  "broken XML",
			appFs: afero.NewMemMapFs(),
			xmlFileNames: map[string]string{
				"/pub/projects/security/oval/opensuse.leap.15.0.xml": "testdata/broken-oval-data.xml",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed Update OVAL: failed to decode SUSE XML: XML syntax error on line 56: element <oval_definitions> closed by </definitions>",
			suseOSes:         map[string][]string{suse.OpenSUSELeap: {"15.0"}},
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
				b, err := ioutil.ReadFile(filePath)
				assert.NoError(t, err, tc.name)
				_, err = w.Write(b)
				assert.NoError(t, err, tc.name)
			}))
			defer ts.Close()
			url := ts.URL + "/pub/projects/security/oval/%s.%s.xml"
			c := suse.Config{
				VulnListDir: "/tmp",
				URL:         url,
				AppFs:       tc.appFs,
				Retry:       0,
			}
			if len(tc.suseOSes) != 0 {
				suse.SuseOSes = tc.suseOSes
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
			assert.NoError(t, err, tc.name)
			assert.Equal(t, len(tc.goldenFiles), fileCount, tc.name)
		})
	}

}
