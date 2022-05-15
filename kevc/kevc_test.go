package kevc_test

import (
	"github.com/aquasecurity/vuln-list-update/kevc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestUpdate(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy/known_exploited_vulnerabilities.json",
		},
		{
			name:      "sad path, invalid json",
			inputFile: "testdata/sad/known_exploited_vulnerabilities.json",
			wantErr:   "failed to KEVC json unmarshal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, err := ioutil.ReadFile(tt.inputFile)
				assert.NoError(t, err, tt.name)
				_, err = w.Write(b)
				assert.NoError(t, err, tt.name)
			}))
			defer ts.Close()

			tmpDir := t.TempDir()
			cc := kevc.NewConfig(kevc.WithURL(ts.URL+"/sites/default/files/feeds/known_exploited_vulnerabilities.json"), kevc.WithDir(tmpDir), kevc.WithRetry(0))

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
