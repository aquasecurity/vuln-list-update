package alpineunfixed_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	alpine "github.com/aquasecurity/vuln-list-update/alpine-unfixed"
)

func TestUpdater_Update(t *testing.T) {
	tests := []struct {
		name        string
		servedFiles map[string]string
		wantErr     string
		goldenFiles map[string]string
	}{
		{
			name: "happy path",
			servedFiles: map[string]string{
				"/all.tar.gz": "testdata/happy/all.tar.gz",
			},
			goldenFiles: map[string]string{
				"alpine-unfixed/CVE-2019-1003051.json": "testdata/golden/CVE-2019-1003051.json",
			},
		},
		{
			name: "broken JSON",
			servedFiles: map[string]string{
				"/all.tar.gz": "testdata/broken/all.tar.gz",
			},
			goldenFiles: map[string]string{
				"alpine-unfixed/CVE-2019-1003051.json": "testdata/golden/CVE-2019-1003051.json",
			},
			wantErr: "JSON decode error",
		},
		{
			name: "404",
			goldenFiles: map[string]string{
				"alpine-unfixed/CVE-2019-1003051.json": "testdata/golden/CVE-2019-1003051.json",
			},
			wantErr: "bad response code: 404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if fileName, ok := tt.servedFiles[r.URL.Path]; !ok {
					http.NotFound(w, r)
					return
				} else {
					fmt.Println(fileName)
					http.ServeFile(w, r, fileName)
				}
			}))
			defer ts.Close()

			tmpDir := t.TempDir()
			u := alpine.NewUpdater(alpine.WithURL(ts.URL+"/all.tar.gz"), alpine.WithVulnListDir(tmpDir))
			err := u.Update()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			assert.NoError(t, err)

			fileCount := 0
			err = filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
				require.NoError(t, err)

				if info.IsDir() {
					return nil
				}
				fileCount++

				got, err := os.ReadFile(path)
				assert.NoError(t, err, path)

				relPath, err := filepath.Rel(tmpDir, path)
				require.NoError(t, err)

				goldenPath, ok := tt.goldenFiles[relPath]
				require.True(t, ok, path)

				want, err := os.ReadFile(goldenPath)
				assert.NoError(t, err, goldenPath)

				assert.JSONEq(t, string(want), string(got))

				return nil
			})
			require.NoError(t, err)
			assert.Equal(t, len(tt.goldenFiles), fileCount)
		})
	}
}
