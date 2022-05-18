package debian

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig_Update(t *testing.T) {
	tests := []struct {
		name       string
		filepath   string
		goldenPath string
		wantErr    string
	}{
		{
			name:       "happy path",
			filepath:   "testdata/happy.json",
			goldenPath: "testdata/golden.json",
		},
		{
			name:    "sad path. 404",
			wantErr: "failed to get list of end-of-life dates from url: failed to fetch URL",
		},
		{
			name:     "sad path. Empty json has been returned",
			filepath: "testdata/empty.json",
			wantErr:  "list of end-of-life dates is empty",
		},
		{
			name:     "sad path. Bad json has been returned",
			filepath: "testdata/sad.json",
			wantErr:  "unable to get EOL dates from",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if test.filepath != "" {
					http.ServeFile(w, r, test.filepath)
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer ts.Close()

			tmpDir, _ := os.MkdirTemp("", "eol-"+distName)
			filePath := filepath.Join(tmpDir, dirPath, fileName)

			c := NewConfig(WithVulnListDir(tmpDir), WithURL(ts.URL), WithRetry(1))

			err := c.Update()

			if test.wantErr != "" {
				assert.NotNil(t, err)
				assert.NoFileExists(t, filePath)
				assert.ErrorContains(t, err, test.wantErr)
			} else {
				assert.Nil(t, err)
				assert.FileExists(t, filePath)

				gotJson, err := os.ReadFile(filePath)
				assert.NoError(t, err)

				wantJson, err := os.ReadFile(test.goldenPath)
				assert.NoError(t, err)

				assert.JSONEq(t, string(wantJson), string(gotJson))
			}
		})
	}
}
