package alpineunfix

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/spf13/afero"
)

func TestUpdater_Update(t *testing.T) {
	type fields struct {
		appFs            afero.Fs
		retry            int
		homeFiles        map[string]string
		fileDownloadPath string
	}
	tests := []struct {
		name        string
		fields      fields
		wantErr     bool
		goldenFiles map[string]string
	}{
		{
			name: "happy path", fields: fields{
				appFs:            afero.NewOsFs(),
				retry:            0,
				fileDownloadPath: "unfix",
				homeFiles: map[string]string{
					"/": "testdata/happy_path/all.tar.gz",
				},
			}, wantErr: false,
			goldenFiles: map[string]string{
				"testdata/outfiles/alpine-unfix/CVE-2019-1003051.json": "testdata/golden/CVE-2019-1003051.json",
			},
		},
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
			fileDownloadPath := filepath.Join(vulnListDir, tt.fields.fileDownloadPath)
			defer os.RemoveAll(vulnListDir)
			u := Updater{
				vulnListDir:      vulnListDir,
				appFs:            tt.fields.appFs,
				baseURL:          home.URL,
				fileDownloadPath: fileDownloadPath,
				retry:            tt.fields.retry,
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
				var expectedJson AlpineUnfix
				err = json.Unmarshal(expected, &expectedJson)
				assert.NoError(t, err, path)
				var actualJson AlpineUnfix
				err = json.Unmarshal(actual, &actualJson)
				assert.Equal(t, expectedJson, actualJson, "")

				return nil
			})
			assert.Equal(t, len(tt.goldenFiles), fileCount)
			assert.NoError(t, err)
		})
	}
}
