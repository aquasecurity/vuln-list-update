package kevc_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/kevc"
)

func TestUpdate(t *testing.T) {
	tests := []struct {
		name         string
		inputFileDir string
		wantErr      string
	}{
		{
			name:         "happy path",
			inputFileDir: "testdata/happy/",
		},
		{
			name:         "sad path, invalid json",
			inputFileDir: "testdata/sad/",
			wantErr:      "failed to KEVC json unmarshal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.FileServer(http.Dir(tt.inputFileDir)))
			defer ts.Close()

			tmpDir := t.TempDir()
			cc := kevc.NewConfig(
				kevc.WithURL(ts.URL+"/known_exploited_vulnerabilities.json"),
				kevc.WithDir(tmpDir),
				kevc.WithRetry(0),
			)

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
