package alpine

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
			filepath:   "testdata/eol.html",
			goldenPath: "testdata/alpine.json",
		},
		{
			name:    "sad path. 404",
			wantErr: "failed to get list of end-of-life dates from url: failed to fetch URL:",
		},
		{
			name:     "sad path. HTML doesn't have table",
			filepath: "testdata/no-table.html",
			wantErr:  "List of end-of-life dates is empty.",
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

			tmpDir, _ := os.MkdirTemp("", "eol-alpine")
			filePath := filepath.Join(tmpDir, eolAlpineFolder, eolAlpineFile)

			c := NewConfig(WithVulnListDir(tmpDir), WithEolURL(ts.URL), WithRetry(1))

			err := c.Update()

			if test.wantErr != "" {
				assert.NotNil(t, err)
				assert.NoFileExists(t, filePath)
				assert.ErrorContains(t, err, test.wantErr)
			} else {
				assert.Nil(t, err)
				assert.FileExists(t, filePath)

				wantJson, err := os.ReadFile(filePath)
				assert.NoError(t, err)

				gotJson, err := os.ReadFile(test.goldenPath)
				assert.NoError(t, err)

				assert.JSONEq(t, string(wantJson), string(gotJson))
			}
		})

	}
}
