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
		name      string
		gzipFile  string
		wantFiles []string
		wantErr   string
	}{
		{
			name:     "happy path",
			gzipFile: "testdata/updateinfo.xml.gz",
			wantFiles: []string{
				"BRSA-1bwujdrkn6nc.json",
				"BRSA-kdg8bd1th2gb.json",
			},
		},
		{
			name:     "invalid gzip",
			gzipFile: "testdata/updateinfo_invalid.xml.gz",
			wantErr:  "failed to decompress updateinfo",
		},
		{
			name:     "invalid xml",
			gzipFile: "testdata/invalid_xml.gz",
			wantErr:  "failed to decode updateinfo XML",
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
			c := bottlerocket.NewConfig(
				bottlerocket.WithURL(fmt.Sprintf("%s/updateinfo.xml.gz", ts.URL)),
				bottlerocket.WithVulnListDir(tmpDir),
			)

			err := c.Update()
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)

			entries, err := os.ReadDir(filepath.Join(tmpDir, "bottlerocket"))
			require.NoError(t, err)
			assert.Len(t, entries, len(tc.wantFiles))

			for _, wantFile := range tc.wantFiles {
				got, err := os.ReadFile(filepath.Join(tmpDir, "bottlerocket", wantFile))
				require.NoError(t, err, "failed to open the result file")

				want, err := os.ReadFile(filepath.Join("testdata", "golden", wantFile))
				require.NoError(t, err, "failed to open the golden file")

				assert.JSONEq(t, string(want), string(got))
			}
		})
	}
}
