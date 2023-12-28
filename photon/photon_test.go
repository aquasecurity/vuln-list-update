package photon_test

import (
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/photon"
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
				"/photon_cve_metadata/photon_versions.json":    "testdata/photon_versions.json",
				"/photon_cve_metadata/cve_data_photon1.0.json": "testdata/cve_data_photon1.0.json",
				"/photon_cve_metadata/cve_data_photon2.0.json": "testdata/cve_data_photon2.0.json",
				"/photon_cve_metadata/cve_data_photon3.0.json": "testdata/cve_data_photon3.0.json",
			},
			goldenFiles: map[string]string{
				"/tmp/photon/1.0/zlib/CVE-2016-9843.json":           "testdata/golden/CVE-2016-9843.json",
				"/tmp/photon/1.0/zookeeper/CVE-2017-5637.json":      "testdata/golden/CVE-2017-5637.json",
				"/tmp/photon/1.0/apache-tomcat/CVE-2017-12617.json": "testdata/golden/CVE-2017-12617.json",
				"/tmp/photon/1.0/binutils/CVE-2018-10372.json":      "testdata/golden/CVE-2018-10372.json",
				"/tmp/photon/1.0/binutils/CVE-2019-12972.json":      "testdata/golden/CVE-2019-12972.json",
				"/tmp/photon/2.0/jq/CVE-2015-8863.json":             "testdata/golden/CVE-2015-8863.json",
				"/tmp/photon/2.0/bash/CVE-2016-9401.json":           "testdata/golden/CVE-2016-9401.json",
				"/tmp/photon/2.0/ansible/CVE-2017-7473.json":        "testdata/golden/CVE-2017-7473.json",
				"/tmp/photon/2.0/ansible/CVE-2018-16876.json":       "testdata/golden/CVE-2018-16876.json",
				"/tmp/photon/2.0/ansible/CVE-2019-10156.json":       "testdata/golden/CVE-2019-10156.json",
				"/tmp/photon/3.0/ansible/CVE-2019-3828.json":        "testdata/golden/CVE-2019-3828.json",
				"/tmp/photon/3.0/apache-tomcat/CVE-2019-0199.json":  "testdata/golden/CVE-2019-0199.json",
				"/tmp/photon/3.0/apache-tomcat/CVE-2019-10072.json": "testdata/golden/CVE-2019-10072.json",
				"/tmp/photon/3.0/binutils/CVE-2017-16826.json":      "testdata/golden/CVE-2017-16826.json",
			},
		},
		{
			name:  "invalid photon_versions.json",
			appFs: afero.NewReadOnlyFs(afero.NewOsFs()),
			bzip2FileNames: map[string]string{
				"/photon_cve_metadata/photon_versions.json": "testdata/invalid_photon_versions.json",
			},
			expectedErrorMsg: "failed to decode Photon versions",
		},
		{
			name:  "invalid filesystem write read only path",
			appFs: afero.NewReadOnlyFs(afero.NewOsFs()),
			bzip2FileNames: map[string]string{
				"/photon_cve_metadata/photon_versions.json":    "testdata/photon_versions.json",
				"/photon_cve_metadata/cve_data_photon1.0.json": "testdata/cve_data_photon1.0.json",
				"/photon_cve_metadata/cve_data_photon2.0.json": "testdata/cve_data_photon2.0.json",
				"/photon_cve_metadata/cve_data_photon3.0.json": "testdata/cve_data_photon3.0.json",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "unable to create a directory: operation not permitted",
		},
		{
			name:             "404",
			appFs:            afero.NewMemMapFs(),
			bzip2FileNames:   map[string]string{},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to fetch Photon versions",
		},
		{
			name:  "EOF file",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/photon_cve_metadata/photon_versions.json":    "testdata/photon_versions.json",
				"/photon_cve_metadata/cve_data_photon1.0.json": "testdata/invalid.txt",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to unmarshal Photon advisory: unexpected end of JSON input",
		},
		{
			name:  "invalid json format",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/photon_cve_metadata/photon_versions.json":    "testdata/photon_versions.json",
				"/photon_cve_metadata/cve_data_photon1.0.json": "testdata/cve_data_photon_invalid_format.json",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to unmarshal Photon advisory: invalid character ']' after object key:value pair",
		},
		{
			name:  "invalid CVE-ID",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/photon_cve_metadata/photon_versions.json":    "testdata/photon_versions.json",
				"/photon_cve_metadata/cve_data_photon1.0.json": "testdata/cve_data_photon3.0_invalid_cveid.json",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "invalid CVE-ID format",
		},
		{
			name:  "empty CVE-ID",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/photon_cve_metadata/photon_versions.json":    "testdata/photon_versions.json",
				"/photon_cve_metadata/cve_data_photon1.0.json": "testdata/cve_data_photon1.0.json",
				"/photon_cve_metadata/cve_data_photon2.0.json": "testdata/cve_data_photon_empty_cveid.json",
				"/photon_cve_metadata/cve_data_photon3.0.json": "testdata/cve_data_photon3.0.json",
			},
			goldenFiles: map[string]string{
				"/tmp/photon/1.0/zlib/CVE-2016-9843.json":           "testdata/golden/CVE-2016-9843.json",
				"/tmp/photon/1.0/zookeeper/CVE-2017-5637.json":      "testdata/golden/CVE-2017-5637.json",
				"/tmp/photon/1.0/apache-tomcat/CVE-2017-12617.json": "testdata/golden/CVE-2017-12617.json",
				"/tmp/photon/1.0/binutils/CVE-2018-10372.json":      "testdata/golden/CVE-2018-10372.json",
				"/tmp/photon/1.0/binutils/CVE-2019-12972.json":      "testdata/golden/CVE-2019-12972.json",
				"/tmp/photon/3.0/ansible/CVE-2019-3828.json":        "testdata/golden/CVE-2019-3828.json",
				"/tmp/photon/3.0/apache-tomcat/CVE-2019-0199.json":  "testdata/golden/CVE-2019-0199.json",
				"/tmp/photon/3.0/apache-tomcat/CVE-2019-10072.json": "testdata/golden/CVE-2019-10072.json",
				"/tmp/photon/3.0/binutils/CVE-2017-16826.json":      "testdata/golden/CVE-2017-16826.json",
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
				b, err := os.ReadFile(filePath)
				assert.NoError(t, err, tc.name)
				_, err = w.Write(b)
				assert.NoError(t, err, tc.name)
			}))
			defer ts.Close()
			url := ts.URL + "/photon_cve_metadata/"
			c := photon.Config{
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
