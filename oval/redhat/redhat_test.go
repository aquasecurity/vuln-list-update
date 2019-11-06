package redhat

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/spf13/afero"
)

var update = flag.Bool("update", false, "update golden files")

func TestConfig_Update(t *testing.T) {
	testCases := []struct {
		name             string
		bzip2FileNames   map[string]string
		goldenFiles      map[string]string
		expectedErrorMsg string
	}{
		{
			name: "happy path",
			bzip2FileNames: map[string]string{
				"/RHEL6/rhel-6.oval.xml.bz2": "testdata/rhel-6.oval.xml.bz2",
				"/RHEL7/rhel-7.oval.xml.bz2": "testdata/rhel-7.oval.xml.bz2",
				"/RHEL8/rhel-8.oval.xml.bz2": "testdata/rhel-8.oval.xml.bz2",
			},
			goldenFiles: map[string]string{
				"/tmp/oval/redhat/6/2011/RHBA-2011:1656.json": "testdata/golden/RHBA-2011:1656.json",

				"/tmp/oval/redhat/7/2015/RHBA-2015:0364.json": "testdata/golden/RHBA-2015:0364.json",
				"/tmp/oval/redhat/7/2015/RHBA-2015:0386.json": "testdata/golden/RHBA-2015:0386.json",
				"/tmp/oval/redhat/7/2015/RHBA-2015:0441.json": "testdata/golden/RHBA-2015:0441.json",

				"/tmp/oval/redhat/8/2019/RHSA-2019:0966.json": "testdata/golden/RHSA-2019:0966.json",
				"/tmp/oval/redhat/8/2019/RHSA-2019:0968.json": "testdata/golden/RHSA-2019:0968.json",
			},
		},
		{
			name:             "404",
			bzip2FileNames:   map[string]string{},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to fetch Red Hat OVAL: failed to fetch URL: HTTP error. status code: 404, url:",
		},
		{
			name: "invalid file format",
			bzip2FileNames: map[string]string{
				"/RHEL6/rhel-6.oval.xml.bz2": "testdata/test.txt",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to unmarshal Red Hat OVAL XML: bzip2 data invalid: bad magic value",
		},
		{
			name: "broken XML",
			bzip2FileNames: map[string]string{
				"/RHEL6/rhel-6.oval.xml.bz2": "testdata/rhel-6-broken.oval.xml.bz2",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to unmarshal Red Hat OVAL XML: XML syntax error on line 42: unexpected EOF",
		},
		{
			name: "invalid RHSA-ID is ignored",
			bzip2FileNames: map[string]string{
				"/RHEL6/rhel-6.oval.xml.bz2": "testdata/rhel-6-invalid-id.oval.xml.bz2",
				"/RHEL7/rhel-7.oval.xml.bz2": "testdata/rhel-7.oval.xml.bz2",
				"/RHEL8/rhel-8.oval.xml.bz2": "testdata/rhel-8.oval.xml.bz2",
			},
			goldenFiles: map[string]string{
				"/tmp/oval/redhat/7/2015/RHBA-2015:0364.json": "testdata/golden/RHBA-2015:0364.json",
				"/tmp/oval/redhat/7/2015/RHBA-2015:0386.json": "testdata/golden/RHBA-2015:0386.json",
				"/tmp/oval/redhat/7/2015/RHBA-2015:0441.json": "testdata/golden/RHBA-2015:0441.json",

				"/tmp/oval/redhat/8/2019/RHSA-2019:0966.json": "testdata/golden/RHSA-2019:0966.json",
				"/tmp/oval/redhat/8/2019/RHSA-2019:0968.json": "testdata/golden/RHSA-2019:0968.json",
			},
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

			u := ts.URL + "/RHEL%s/rhel-%s.oval.xml.bz2"
			fmt.Println(u)
			appFs := afero.NewMemMapFs()
			c := Config{
				VulnListDir: "/tmp",
				URLFormat:   u,
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

func TestConfig_saveRHSAPerYear(t *testing.T) {
	testCases := []struct {
		name          string
		rhsaID        string
		inputData     string
		expectedError error
	}{
		{
			name:      "happy path",
			rhsaID:    "RHSA-2018:0094",
			inputData: `{}`,
		},
		{
			name:          "sad path: invalid rhsaid format",
			rhsaID:        "foobarbaz",
			inputData:     `{}`,
			expectedError: errors.New("invalid RHSA-ID format: foobarbaz"),
		},
	}

	for _, tc := range testCases {
		c := Config{
			AppFs: afero.NewMemMapFs(),
		}

		d, _ := ioutil.TempDir("", "TestConfig_saveRHSAPerYear-*")
		defer func() {
			_ = os.RemoveAll(d)
		}()

		err := c.saveRHSAPerYear(d, tc.rhsaID, tc.inputData)
		switch {
		case tc.expectedError != nil:
			assert.Equal(t, tc.expectedError.Error(), err.Error(), tc.name)
		default:
			assert.NoError(t, err, tc.name)
		}
	}
}
