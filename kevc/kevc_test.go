package kevc_test

import (
	"fmt"
	"github.com/aquasecurity/vuln-list-update/kevc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestUpdate(t *testing.T) {
	tests := []struct {
		name        string
		servedFiles map[string]string
		wantErr     string
	}{
		{
			name: "happy path",
			servedFiles: map[string]string{
				"/known_exploited_vulnerabilities.json": "testdata/happy/known_exploited_vulnerabilities.json",
			},
		},
		{
			name: "sad path, invalid json",
			servedFiles: map[string]string{
				"/known_exploited_vulnerabilities.json": "testdata/sad/known_exploited_vulnerabilities.json",
			},
			wantErr: "failed to KEVC json unmarshal",
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
			cc := kevc.NewConfig(kevc.WithURL(ts.URL+"/known_exploited_vulnerabilities.json"), kevc.WithDir(tmpDir), kevc.WithRetry(0))

			err := cc.Update()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			err = filepath.Walk(tmpDir, func(path string, info os.FileInfo, errfp error) error {
				if errfp != nil {
					return errfp
				}
				if info.IsDir() {
					return nil
				}

				dir, file := filepath.Split(path)
				want, err := os.ReadFile(filepath.Join("testdata", "golden", "kevc", filepath.Base(dir), file))
				assert.NoError(t, err, "failed to open the golden file")

				got, err := os.ReadFile(path)
				assert.NoError(t, err, "failed to open the result file")

				assert.JSONEq(t, string(want), string(got))

				return nil
			})
			require.NoError(t, err, tt.name)
		})
	}
}
