package redhat

import (
	"errors"
	"flag"
	"strings"

	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
			name: "happy path ",

			bzip2FileNames: map[string]string{
				"/PULP_MANIFEST": "testdata/PULP_MANIFEST",
				"/RHEL6/rhel-6-extras-including-unpatched.oval.xml.bz2": "testdata/rhel-6-extras-including-unpatched.oval.xml.bz2",
				"/RHEL7/dotnet-3.1-including-unpatched.oval.xml.bz2":    "testdata/dotnet-3.1-including-unpatched.oval.xml.bz2",
				"/RHEL8/ansible-2-including-unpatched.oval.xml.bz2":     "testdata/ansible-2-including-unpatched.oval.xml.bz2",
			},
			goldenFiles: map[string]string{
				"/tmp/oval/redhat/6/rhel-6-extras-including-unpatched/definitions/2014/CVE-2014-3209.json":            "testdata/golden/rhel-6-extras-including-unpatched/CVE-2014-3209.json",
				"/tmp/oval/redhat/6/rhel-6-extras-including-unpatched/definitions/2016/CVE-2016-5361.json":            "testdata/golden/rhel-6-extras-including-unpatched/CVE-2016-5361.json",
				"/tmp/oval/redhat/6/rhel-6-extras-including-unpatched/definitions/2018/CVE-2018-5389.json":            "testdata/golden/rhel-6-extras-including-unpatched/CVE-2018-5389.json",
				"/tmp/oval/redhat/6/rhel-6-extras-including-unpatched/definitions/2020/CVE-2020-28935.json":           "testdata/golden/rhel-6-extras-including-unpatched/CVE-2020-28935.json",
				"/tmp/oval/redhat/6/rhel-6-extras-including-unpatched/definitions/2014/RHBA-2014:1396.json":           "testdata/golden/rhel-6-extras-including-unpatched/RHBA-2014-1396.json",
				"/tmp/oval/redhat/6/rhel-6-extras-including-unpatched/definitions/2016/CVE-2016-5391.unaffected.json": "testdata/golden/rhel-6-extras-including-unpatched/CVE-2016-5391.unaffected.json",
				"/tmp/oval/redhat/6/rhel-6-extras-including-unpatched/objects/objects.json":                           "testdata/golden/rhel-6-extras-including-unpatched/objects.json",
				"/tmp/oval/redhat/6/rhel-6-extras-including-unpatched/states/states.json":                             "testdata/golden/rhel-6-extras-including-unpatched/states.json",
				"/tmp/oval/redhat/6/rhel-6-extras-including-unpatched/tests/tests.json":                               "testdata/golden/rhel-6-extras-including-unpatched/tests.json",

				"/tmp/oval/redhat/7/dotnet-3.1-including-unpatched/definitions/2020/RHSA-2020:0134.json":           "testdata/golden/dotnet-3.1-including-unpatched/RHSA-2020-0134.json",
				"/tmp/oval/redhat/7/dotnet-3.1-including-unpatched/definitions/2020/RHSA-2020:2249.json":           "testdata/golden/dotnet-3.1-including-unpatched/RHSA-2020-2249.json",
				"/tmp/oval/redhat/7/dotnet-3.1-including-unpatched/definitions/2020/CVE-2020-0605.unaffected.json": "testdata/golden/dotnet-3.1-including-unpatched/CVE-2020-0605.unaffected.json",
				"/tmp/oval/redhat/7/dotnet-3.1-including-unpatched/definitions/2020/CVE-2020-0606.unaffected.json": "testdata/golden/dotnet-3.1-including-unpatched/CVE-2020-0606.unaffected.json",
				"/tmp/oval/redhat/7/dotnet-3.1-including-unpatched/objects/objects.json":                           "testdata/golden/dotnet-3.1-including-unpatched/objects.json",
				"/tmp/oval/redhat/7/dotnet-3.1-including-unpatched/states/states.json":                             "testdata/golden/dotnet-3.1-including-unpatched/states.json",
				"/tmp/oval/redhat/7/dotnet-3.1-including-unpatched/tests/tests.json":                               "testdata/golden/dotnet-3.1-including-unpatched/tests.json",

				"/tmp/oval/redhat/8/ansible-2-including-unpatched/definitions/2020/CVE-2020-10744.json": "testdata/golden/ansible-2-including-unpatched/CVE-2020-10744.json",
				"/tmp/oval/redhat/8/ansible-2-including-unpatched/definitions/2020/CVE-2020-1734.json":  "testdata/golden/ansible-2-including-unpatched/CVE-2020-1734.json",
				"/tmp/oval/redhat/8/ansible-2-including-unpatched/definitions/2020/CVE-2020-1738.json":  "testdata/golden/ansible-2-including-unpatched/CVE-2020-1738.json",
				"/tmp/oval/redhat/8/ansible-2-including-unpatched/definitions/2019/RHSA-2019:3927.json": "testdata/golden/ansible-2-including-unpatched/RHSA-2019-3927.json",
				"/tmp/oval/redhat/8/ansible-2-including-unpatched/definitions/2020/RHSA-2020:0215.json": "testdata/golden/ansible-2-including-unpatched/RHSA-2020-0215.json",
				"/tmp/oval/redhat/8/ansible-2-including-unpatched/objects/objects.json":                 "testdata/golden/ansible-2-including-unpatched/objects.json",
				"/tmp/oval/redhat/8/ansible-2-including-unpatched/states/states.json":                   "testdata/golden/ansible-2-including-unpatched/states.json",
				"/tmp/oval/redhat/8/ansible-2-including-unpatched/tests/tests.json":                     "testdata/golden/ansible-2-including-unpatched/tests.json",
			},
		},
		{
			name: "404",
			bzip2FileNames: map[string]string{
				"/PULP_MANIFEST": "testdata/PULP_MANIFEST",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to fetch Red Hat OVAL v2: failed to fetch URL: HTTP error. status code: 404, url:",
		},
		{
			name: "invalid file format",
			bzip2FileNames: map[string]string{
				"/PULP_MANIFEST": "testdata/PULP_MANIFEST",
				"/RHEL6/rhel-6-extras-including-unpatched.oval.xml.bz2": "testdata/test.txt",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to unmarshal Red Hat OVAL v2 XML: bzip2 data invalid: bad magic value",
		},
		{
			name: "broken XML",
			bzip2FileNames: map[string]string{
				"/PULP_MANIFEST": "testdata/PULP_MANIFEST",
				"/RHEL6/rhel-6-extras-including-unpatched.oval.xml.bz2": "testdata/rhel-6-extras-including-unpatched-broken-XML.oval.xml.bz2",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to unmarshal Red Hat OVAL v2 XML: XML syntax error on line 411: element",
		},
	}
	for _, tc := range testCases {
		dataPath := "/security/data/oval/v2"
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p := strings.TrimPrefix(r.URL.Path, dataPath)
				filePath, ok := tc.bzip2FileNames[p]
				if !ok {
					http.NotFound(w, r)
					return
				}
				b, err := ioutil.ReadFile(filePath)
				require.NoError(t, err, tc.name)

				_, err = w.Write(b)
				assert.NoError(t, err, tc.name)
			}))
			defer ts.Close()

			appFs := afero.NewMemMapFs()
			c := Config{
				VulnListDir: "/tmp",
				URLFormat:   ts.URL + dataPath + "/%s",
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
				fileCount++

				actual, err := afero.ReadFile(appFs, path)
				assert.NoError(t, err, tc.name)

				goldenPath, ok := tc.goldenFiles[path]
				assert.True(t, ok, tc.name)
				if *update {
					err = ioutil.WriteFile(goldenPath, actual, 0666)
					require.NoError(t, err, tc.name)
				}
				expected, err := ioutil.ReadFile(goldenPath)
				assert.NoError(t, err, tc.name)

				assert.Equal(t, string(expected), string(actual), path)

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
		inputData     Definition
		expectedError error
	}{
		{
			name:      "happy path",
			rhsaID:    "RHSA-2018:0094",
			inputData: Definition{},
		},
		{
			name:          "sad path: invalid RHSA-ID format",
			rhsaID:        "foobarbaz",
			inputData:     Definition{},
			expectedError: errors.New("invalid RHSA-ID format"),
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

		err := c.saveAdvisoryPerYear(d, tc.rhsaID, tc.inputData)
		switch {
		case tc.expectedError != nil:
			assert.Equal(t, tc.expectedError.Error(), err.Error(), tc.name)
		default:
			assert.NoError(t, err, tc.name)
		}
	}
}
