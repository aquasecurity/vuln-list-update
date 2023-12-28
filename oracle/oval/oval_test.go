package oval_test

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/vuln-list-update/oracle/oval"
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
				"/oval/com.oracle.elsa-all.xml.bz2": "testdata/all-positive-data.xml.bz2",
			},
			goldenFiles: map[string]string{
				"/tmp/oval/oracle/2007/ELSA-2007-0057.json": "testdata/golden/ELSA-2007-0057.json",
				"/tmp/oval/oracle/2008/ELSA-2008-0110.json": "testdata/golden/ELSA-2008-0110.json",
				"/tmp/oval/oracle/2009/ELSA-2009-1203.json": "testdata/golden/ELSA-2009-1203.json",
				"/tmp/oval/oracle/2010/ELSA-2010-0809.json": "testdata/golden/ELSA-2010-0809.json",
				"/tmp/oval/oracle/2011/ELSA-2011-1268.json": "testdata/golden/ELSA-2011-1268.json",
				"/tmp/oval/oracle/2012/ELSA-2012-1261.json": "testdata/golden/ELSA-2012-1261.json",
				"/tmp/oval/oracle/2013/ELSA-2013-1732.json": "testdata/golden/ELSA-2013-1732.json",
				"/tmp/oval/oracle/2014/ELSA-2014-2010.json": "testdata/golden/ELSA-2014-2010.json",
				"/tmp/oval/oracle/2015/ELSA-2015-2561.json": "testdata/golden/ELSA-2015-2561.json",
				"/tmp/oval/oracle/2016/ELSA-2016-3646.json": "testdata/golden/ELSA-2016-3646.json",
				"/tmp/oval/oracle/2017/ELSA-2017-3516.json": "testdata/golden/ELSA-2017-3516.json",
				"/tmp/oval/oracle/2018/ELSA-2018-3410.json": "testdata/golden/ELSA-2018-3410.json",
				"/tmp/oval/oracle/2019/ELSA-2019-4820.json": "testdata/golden/ELSA-2019-4820.json",
				"/tmp/oval/oracle/2019/ELSA-2019-4821.json": "testdata/golden/ELSA-2019-4821.json",
			},
		},
		{
			name:  "positive test file format ELSA-XXXX-XXXX-X",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/oval/com.oracle.elsa-all.xml.bz2": "testdata/elsa-2018-1196-1.xml.bz2",
			},
			goldenFiles: map[string]string{
				"/tmp/oval/oracle/2018/ELSA-2018-1196-1.json": "testdata/golden/ELSA-2018-1196-1.json",
			},
			expectedErrorMsg: "",
		},
		{
			name:  "invalid filesystem write read only path",
			appFs: afero.NewReadOnlyFs(afero.NewOsFs()),
			bzip2FileNames: map[string]string{
				"/oval/com.oracle.elsa-all.xml.bz2": "testdata/all-positive-data.xml.bz2",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "unable to create a directory: operation not permitted",
		},
		{
			name:  "invalid title format",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/oval/com.oracle.elsa-all.xml.bz2": "testdata/invalid-title-format.xml.bz2",
			},
			goldenFiles: map[string]string{
				"/tmp/oval/oracle/2007/ELSA-2007-0057.json": "testdata/golden/ELSA-2007-0057.json",
			},
		},
		{
			name:             "404",
			appFs:            afero.NewMemMapFs(),
			bzip2FileNames:   map[string]string{},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to fetch Oracle Linux OVAL: failed to fetch URL: HTTP error. status code: 404, url:",
		},
		{
			name:  "invalid file format",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/oval/com.oracle.elsa-all.xml.bz2": "testdata/invalid.txt",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to decode Oracle Linux OVAL XML: bzip2 data invalid: bad magic value",
		},
		{
			name:  "empty file format",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/oval/com.oracle.elsa-all.xml.bz2": "testdata/EOF.txt",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to decode Oracle Linux OVAL XML: unexpected EOF",
		},
		{
			name:  "broken XML",
			appFs: afero.NewMemMapFs(),
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
				b, err := os.ReadFile(filePath)
				assert.NoError(t, err, tc.name)
				_, err = w.Write(b)
				assert.NoError(t, err, tc.name)
			}))
			defer ts.Close()
			url := ts.URL + "/oval/com.oracle.elsa-all.xml.bz2"
			c := oval.Config{
				VulnListDir: "/tmp",
				URL:         url,
				AppFs:       tc.appFs,
				Retry:       0,
			}
			err := c.Update()
			switch {
			case tc.expectedErrorMsg != "":
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
					err = os.WriteFile(goldenPath, actual, 0666)
					assert.NoError(t, err, tc.name)
				}

				expected, err := os.ReadFile(goldenPath)
				assert.NoError(t, err, tc.name)

				assert.Equal(t, expected, actual, tc.name)

				return nil
			})
			assert.Equal(t, len(tc.goldenFiles), fileCount, tc.name)
			assert.NoError(t, err, tc.name)
		})
	}

}
