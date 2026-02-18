package bottlerocket_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/bottlerocket"
)

func TestConfig_Update(t *testing.T) {
	testCases := []struct {
		name     string
		gzipFile string
		wantErr  bool
	}{
		{
			name:     "happy path",
			gzipFile: "testdata/updateinfo.xml.gz",
		},
		{
			name:     "invalid gzip",
			gzipFile: "testdata/updateinfo_invalid.xml.gz",
			wantErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				buf, err := os.ReadFile(tc.gzipFile)
				require.NoError(t, err)
				_, _ = w.Write(buf)
			}))
			defer ts.Close()

			tmpDir := t.TempDir()
			c := bottlerocket.NewConfig(bottlerocket.With(
				fmt.Sprintf("%s/updateinfo.xml.gz", ts.URL),
				tmpDir,
			))

			err := c.Update()
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			err = filepath.Walk(tmpDir, func(path string, info os.FileInfo, errfp error) error {
				if info.IsDir() {
					return nil
				}
				filename := filepath.Base(path)
				golden := filepath.Join("testdata", filename+".golden")

				want, err := os.ReadFile(golden)
				assert.NoError(t, err, "failed to open the golden file")

				got, err := os.ReadFile(path)
				assert.NoError(t, err, "failed to open the result file")

				assert.JSONEq(t, string(want), string(got))

				return nil
			})
			assert.NoError(t, err, "filepath walk error")
		})
	}
}
