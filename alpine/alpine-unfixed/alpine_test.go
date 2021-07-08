package alpineunfix

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/spf13/afero"
)

func TestUpdater_Update(t *testing.T) {
	type fields struct {
		appFs     afero.Fs
		retry     int
		homeFiles map[string]string
	}
	tests := []struct {
		name        string
		fields      fields
		wantErr     bool
		goldenFiles map[string]string
	}{
		{name: "", fields: fields{
			appFs: afero.NewOsFs(),
			retry: 0,
			homeFiles: map[string]string{
				"/":                               "testdata/home.html",
				"/branch/edge-main":               "testdata/edge-main.json",
				"/branch/edge-main/vuln-orphaned": "testdata/vuln-orphaned.json",
				"/branch/3.10-main":               "testdata/3.10-main.json",
				"/branch/3.10-main/vuln-orphaned": "testdata/3.10-main_vuln-orphaned.json",
				"/vuln/CVE-2019-6461":             "testdata/CVE-2019-6461.html",
				"/vuln/CVE-2019-12212":            "testdata/CVE-2019-12212.html",
				"/vuln/CVE-2019-12214":            "testdata/CVE-2019-12214.html",
				"/vuln/CVE-2021-31879":            "testdata/CVE-2021-31879.html",
				"/vuln/CVE-2021-26933":            "testdata/CVE-2021-26933.html",
			},
		}, wantErr: false,
			goldenFiles: map[string]string{
				"testdata/outfiles/alpine-unfixed/3.11/main/wget.json":           "testdata/golden/3.11/main/wget.json",
				"testdata/outfiles/alpine-unfixed/3.11/main/cairo.json":          "testdata/golden/3.11/main/cairo.json",
				"testdata/outfiles/alpine-unfixed/edge/community/freeimage.json": "testdata/golden/edge/community/freeimage.json",
				"testdata/outfiles/alpine-unfixed/edge/main/wget.json":           "testdata/golden/edge/main/wget.json",
				"testdata/outfiles/alpine-unfixed/edge/main/cairo.json":          "testdata/golden/edge/main/cairo.json",
				"testdata/outfiles/alpine-unfixed/3.10/main/wget.json":           "testdata/golden/3.10/main/wget.json",
				"testdata/outfiles/alpine-unfixed/3.10/main/xen.json":            "testdata/golden/3.10/main/xen.json",
				"testdata/outfiles/alpine-unfixed/3.14/community/freeimage.json": "testdata/golden/3.14/community/freeimage.json",
				"testdata/outfiles/alpine-unfixed/3.14/main/wget.json":           "testdata/golden/3.14/main/wget.json",
				"testdata/outfiles/alpine-unfixed/3.14/main/cairo.json":          "testdata/golden/3.14/main/cairo.json",
				"testdata/outfiles/alpine-unfixed/3.12/main/wget.json":           "testdata/golden/3.12/main/wget.json",
				"testdata/outfiles/alpine-unfixed/3.12/main/cairo.json":          "testdata/golden/3.12/main/cairo.json",
				"testdata/outfiles/alpine-unfixed/3.13/main/wget.json":           "testdata/golden/3.13/main/wget.json",
				"testdata/outfiles/alpine-unfixed/3.13/main/cairo.json":          "testdata/golden/3.13/main/cairo.json",
			}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if fileName, ok := tt.fields.homeFiles[r.URL.Path]; !ok {
					http.NotFound(w, r)
					return
				} else {
					http.ServeFile(w, r, fileName)
				}
			}))
			defer home.Close()
			vulnListDir := "testdata/outfiles"
			defer os.RemoveAll(vulnListDir)
			u := Updater{
				vulnListDir: vulnListDir,
				appFs:       tt.fields.appFs,
				baseURL:     home.URL,
				retry:       tt.fields.retry,
			}
			if err := u.Update(); (err != nil) != tt.wantErr {
				t.Errorf("Update() error = %v, wantErr %v", err, tt.wantErr)
			}
			fileCount := 0
			err := afero.Walk(tt.fields.appFs, vulnListDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				fileCount++

				actual, err := afero.ReadFile(tt.fields.appFs, path)
				assert.NoError(t, err, path)

				goldenPath, ok := tt.goldenFiles[path]
				require.True(t, ok, path)
				expected, err := ioutil.ReadFile(goldenPath)
				assert.NoError(t, err, goldenPath)
				var expectedJson SaveJsonFormat
				err = json.Unmarshal(expected, &expectedJson)
				assert.NoError(t, err, path)
				var actualJson SaveJsonFormat
				err = json.Unmarshal(actual, &actualJson)
				assert.NoError(t, err, path)
				assert.True(t, expectedJson.PkgName == actualJson.PkgName)
				assert.True(t, expectedJson.RepoName == actualJson.RepoName)
				assert.True(t, expectedJson.DistroVersion == actualJson.DistroVersion)
				for version, actualVuls := range actualJson.UnfixVersion {
					if expVulns, ok := expectedJson.UnfixVersion[version]; !ok {
						assert.True(t, ok)
					} else {
						sort.Strings(actualVuls)
						sort.Strings(expVulns)
						assert.True(t, reflect.DeepEqual(actualVuls, expVulns))
					}
				}
				assert.True(t, expectedJson.DistroVersion == actualJson.DistroVersion)
				require.True(t, reflect.DeepEqual(expectedJson, actualJson), "")

				return nil
			})
			assert.Equal(t, len(tt.goldenFiles), fileCount)
			assert.NoError(t, err)
		})
	}
}
