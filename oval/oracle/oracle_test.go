package oracle_test

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aquasecurity/vuln-list-update/oval/oracle"
	"github.com/stretchr/testify/assert"

	"github.com/spf13/afero"
)

func TestConfig_Update(t *testing.T) {
	testCases := []struct {
		name             string
		bzip2FileNames   map[string]string
		goldenFiles      map[string]string
		expectedErrorMsg string
	}{
		{
			name: "positive test",
			bzip2FileNames: map[string]string{
				"/oval/com.oracle.elsa-all.xml.bz2": "testdata/all-positive-data.xml.bz2",
			},
			goldenFiles: map[string]string{
				"/tmp/oval/oracle/2007/ELSA-2007-0057.json": "testdata/ELSA-2007-0057.json",
				"/tmp/oval/oracle/2008/ELSA-2008-0110.json": "testdata/ELSA-2008-0110.json",
				"/tmp/oval/oracle/2009/ELSA-2009-1203.json": "testdata/ELSA-2009-1203.json",
				"/tmp/oval/oracle/2010/ELSA-2010-0809.json": "testdata/ELSA-2010-0809.json",
				"/tmp/oval/oracle/2011/ELSA-2011-1268.json": "testdata/ELSA-2011-1268.json",
				"/tmp/oval/oracle/2012/ELSA-2012-1261.json": "testdata/ELSA-2012-1261.json",
				"/tmp/oval/oracle/2013/ELSA-2013-1732.json": "testdata/ELSA-2013-1732.json",
				"/tmp/oval/oracle/2014/ELSA-2014-2010.json": "testdata/ELSA-2014-2010.json",
				"/tmp/oval/oracle/2015/ELSA-2015-2561.json": "testdata/ELSA-2015-2561.json",
				"/tmp/oval/oracle/2016/ELSA-2016-3646.json": "testdata/ELSA-2016-3646.json",
				"/tmp/oval/oracle/2017/ELSA-2017-3516.json": "testdata/ELSA-2017-3516.json",
				"/tmp/oval/oracle/2018/ELSA-2018-3410.json": "testdata/ELSA-2018-3410.json",
				"/tmp/oval/oracle/2019/ELSA-2019-4820.json": "testdata/ELSA-2019-4820.json",
				"/tmp/oval/oracle/2019/ELSA-2019-4821.json": "testdata/ELSA-2019-4821.json",
			},
		},
		{
			name: "invalid title format",
			bzip2FileNames: map[string]string{
				"/oval/com.oracle.elsa-all.xml.bz2": "testdata/invalid-title-format.xml.bz2",
			},
			goldenFiles: map[string]string{
				"/tmp/oval/oracle/2007/ELSA-2007-0057.json": "testdata/ELSA-2007-0057.json",
			},
		},
		{
			name:             "404",
			bzip2FileNames:   map[string]string{},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to fetch Oracle Linux OVAL: failed to fetch URL: HTTP error. status code: 404, url:",
		},
		{
			name: "invalid file format",
			bzip2FileNames: map[string]string{
				"/oval/com.oracle.elsa-all.xml.bz2": "testdata/invalid.txt",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to decode Oracle Linux OVAL XML: bzip2 data invalid: bad magic value",
		},
		{
			name: "empty file format",
			bzip2FileNames: map[string]string{
				"/oval/com.oracle.elsa-all.xml.bz2": "testdata/EOF.txt",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to decode Oracle Linux OVAL XML: unexpected EOF",
		},
		{
			name: "broken XML",
			bzip2FileNames: map[string]string{
				"/oval/com.oracle.elsa-all.xml.bz2": "testdata/broken-oval-data.xml.bz2",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to decode Oracle Linux OVAL XML: XML syntax error on line 536: element <criteria> closed by </affected>",
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

			appFs := afero.NewMemMapFs()
			url := ts.URL + "/oval/com.oracle.elsa-all.xml.bz2"
			c := oracle.Config{
				VulnListDir: "/tmp",
				URL:         url,
				AppFs:       appFs,
				Retry:       0,
			}
			err := c.Update()
			switch {
			case tc.expectedErrorMsg != "":
				assert.Contains(t, err.Error(), tc.expectedErrorMsg, tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}

			fileCount := 0
			err = afero.Walk(appFs, "/", func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				fileCount += 1

				actual, err := afero.ReadFile(appFs, path)
				assert.NoError(t, err, tc.name)

				goldenPath, ok := tc.goldenFiles[path]
				assert.True(t, ok, tc.name)

				err = ioutil.WriteFile(goldenPath, actual, 0666)
				assert.NoError(t, err, tc.name)

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
