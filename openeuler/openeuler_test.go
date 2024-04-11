package openeuler_test

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/openeuler"
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
			name:  "positive test openEuler",
			appFs: afero.NewMemMapFs(),
			xmlFileNames: map[string]string{
				"/security/data/cvrf/index.txt":                            "testdata/index.txt",
				"/security/data/cvrf/2021/cvrf-openEuler-SA-2021-1033.xml": "testdata/cvrf-openEuler-SA-2021-1033.xml",
				"/security/data/cvrf/2021/cvrf-openEuler-SA-2021-1202.xml": "testdata/cvrf-openEuler-SA-2021-1202.xml",
				"/security/data/cvrf/2021/cvrf-openEuler-SA-2021-1480.xml": "testdata/cvrf-openEuler-SA-2021-1480.xml",
				"/security/data/cvrf/2022/cvrf-openEuler-SA-2022-1485.xml": "testdata/cvrf-openEuler-SA-2022-1485.xml",
				"/security/data/cvrf/2022/cvrf-openEuler-SA-2022-1580.xml": "testdata/cvrf-openEuler-SA-2022-1580.xml",
				"/security/data/cvrf/2022/cvrf-openEuler-SA-2022-1704.xml": "testdata/cvrf-openEuler-SA-2022-1704.xml",
				"/security/data/cvrf/2023/cvrf-openEuler-SA-2023-1006.xml": "testdata/cvrf-openEuler-SA-2023-1006.xml",
				"/security/data/cvrf/2023/cvrf-openEuler-SA-2023-1010.xml": "testdata/cvrf-openEuler-SA-2023-1010.xml",
				"/security/data/cvrf/2023/cvrf-openEuler-SA-2023-1374.xml": "testdata/cvrf-openEuler-SA-2023-1374.xml",
				"/security/data/cvrf/2024/cvrf-openEuler-SA-2024-1151.xml": "testdata/cvrf-openEuler-SA-2024-1151.xml",
				"/security/data/cvrf/2024/cvrf-openEuler-SA-2024-1295.xml": "testdata/cvrf-openEuler-SA-2024-1295.xml",
				"/security/data/cvrf/2024/cvrf-openEuler-SA-2024-1349.xml": "testdata/cvrf-openEuler-SA-2024-1349.xml",
				"/security/data/cvrf/2022/cvrf-openEuler-SA-2022-1693.xml": "testdata/cvrf-openEuler-SA-2022-1693.xml",
			},
			goldenFiles: map[string]string{
				"/tmp/cvrf/openeuler/2021/openEuler-SA-2021-1033.json": "testdata/golden/openEuler-SA-2021-1033.json",
				"/tmp/cvrf/openeuler/2021/openEuler-SA-2021-1202.json": "testdata/golden/openEuler-SA-2021-1202.json",
				"/tmp/cvrf/openeuler/2021/openEuler-SA-2021-1480.json": "testdata/golden/openEuler-SA-2021-1480.json",
				"/tmp/cvrf/openeuler/2022/openEuler-SA-2022-1485.json": "testdata/golden/openEuler-SA-2022-1485.json",
				"/tmp/cvrf/openeuler/2022/openEuler-SA-2022-1580.json": "testdata/golden/openEuler-SA-2022-1580.json",
				"/tmp/cvrf/openeuler/2022/openEuler-SA-2022-1704.json": "testdata/golden/openEuler-SA-2022-1704.json",
				"/tmp/cvrf/openeuler/2023/openEuler-SA-2023-1006.json": "testdata/golden/openEuler-SA-2023-1006.json",
				"/tmp/cvrf/openeuler/2023/openEuler-SA-2023-1010.json": "testdata/golden/openEuler-SA-2023-1010.json",
				"/tmp/cvrf/openeuler/2023/openEuler-SA-2023-1374.json": "testdata/golden/openEuler-SA-2023-1374.json",
				"/tmp/cvrf/openeuler/2024/openEuler-SA-2024-1151.json": "testdata/golden/openEuler-SA-2024-1151.json",
				"/tmp/cvrf/openeuler/2024/openEuler-SA-2024-1295.json": "testdata/golden/openEuler-SA-2024-1295.json",
				"/tmp/cvrf/openeuler/2024/openEuler-SA-2024-1349.json": "testdata/golden/openEuler-SA-2024-1349.json",
				"/tmp/cvrf/openeuler/2022/openEuler-SA-2022-1693.json": "testdata/golden/openEuler-SA-2022-1693.json",
			},
		},
		{
			name:  "invalid filesystem write read only path",
			appFs: afero.NewReadOnlyFs(afero.NewOsFs()),
			xmlFileNames: map[string]string{
				"/security/data/cvrf/index.txt":                            "testdata/invalid-index.txt",
				"/security/data/cvrf/2021/cvrf-openEuler-SA-2021-1202.xml": "testdata/golden/openEuler-SA-2021-1202.json",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed Update openEuler CVRF: failed to decode openEuler cvrf XML: EOF",
		},
		{
			name:  "empty file format",
			appFs: afero.NewMemMapFs(),
			xmlFileNames: map[string]string{
				"/security/data/cvrf/index.txt":                            "testdata/invalid-index.txt",
				"/security/data/cvrf/2021/cvrf-openEuler-SA-2021-1202.xml": "testdata/EOF.txt",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "",
		},
		{
			name:  "invalid file format",
			appFs: afero.NewMemMapFs(),
			xmlFileNames: map[string]string{
				"/security/data/cvrf/index.txt":                            "testdata/invalid-index.txt",
				"/security/data/cvrf/2021/cvrf-openEuler-SA-2021-1202.xml": "testdata/invalid.txt",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed Update openEuler CVRF: failed to decode openEuler cvrf XML: EOF",
		},
		{
			name:  "broken XML",
			appFs: afero.NewMemMapFs(),
			xmlFileNames: map[string]string{
				"/security/data/cvrf/index.txt":                            "testdata/invalid-index.txt",
				"/security/data/cvrf/2021/cvrf-openEuler-SA-2021-1202.xml": "testdata/broken-cvrf.xml",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed Update openEuler CVRF: failed to decode openEuler cvrf XML: XML syntax error on line 180: unexpected EOF",
		},
	}
	for _, tc := range testCases {
		t.Log("Entering...")
		t.Run(tc.name, func(t *testing.T) {
			t.Log("http ready to start...")
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
			t.Log("http started!")
			defer ts.Close()
			url := ts.URL + "/security/data/cvrf/"
			c := openeuler.Config{
				VulnListDir: "/tmp",
				URL:         url,
				AppFs:       tc.appFs,
				Retry:       0,
			}
			t.Log("updating...")
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
