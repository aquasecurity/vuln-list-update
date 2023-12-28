package wolfi_test

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/wolfi"
)

var update = flag.Bool("update", false, "update golden files")

func TestUpdater_Update(t *testing.T) {
	type fields struct {
		appFs afero.Fs
		retry int
	}
	tests := []struct {
		name        string
		fields      fields
		fileNames   map[string]string
		goldenFiles map[string]string
		wantErr     string
	}{
		{
			name: "happy path",
			fields: fields{
				appFs: afero.NewMemMapFs(),
				retry: 0,
			},
			fileNames: map[string]string{
				"/os/security.json": "testdata/security.json",
			},
			goldenFiles: map[string]string{
				"/tmp/wolfi/os/binutils.json": "testdata/golden/binutils.json",
			},
		},
		{
			name: "404",
			fields: fields{
				appFs: afero.NewMemMapFs(),
				retry: 0,
			},
			fileNames: map[string]string{
				"/": "testdata/index.html",
			},
			wantErr: "status code: 404",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fileName, ok := tt.fileNames[r.URL.Path]
				if !ok {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, fileName)
			}))
			defer ts.Close()

			baseURL, err := url.Parse(ts.URL)
			require.NoError(t, err)

			u := wolfi.NewUpdater(
				wolfi.WithVulnListDir("/tmp"),
				wolfi.WithBaseURL(baseURL),
				wolfi.WithAppFs(tt.fields.appFs))
			err = u.Update()
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				assert.NoError(t, err)
			}

			fileCount := 0
			err = afero.Walk(tt.fields.appFs, "/", func(path string, info os.FileInfo, err error) error {
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
				if *update {
					err = os.WriteFile(goldenPath, actual, 0666)
					require.NoError(t, err, goldenPath)
				}
				expected, err := os.ReadFile(goldenPath)
				assert.NoError(t, err, goldenPath)

				assert.JSONEq(t, string(expected), string(actual), path)

				return nil
			})
			assert.Equal(t, len(tt.goldenFiles), fileCount)
			assert.NoError(t, err)
		})
	}
}
