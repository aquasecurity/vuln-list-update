package govulndb_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vulndb "github.com/aquasecurity/vuln-list-update/go-vulndb"
)

func TestVulnDB_Update(t *testing.T) {
	tests := []struct {
		name      string
		rootDir   string
		wantFiles []string
		wantErr   string
	}{
		{
			name:    "happy path",
			rootDir: "testdata",
			wantFiles: []string{
				filepath.Join("github.com", "apache", "thrift", "GO-2021-0101.json"),
				filepath.Join("github.com", "dhowden", "tag", "GO-2021-0097.json"),
			},
		},
		{
			name:    "sad path",
			rootDir: "unknown",
			wantErr: "HTTP error. status code: 404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := http.FileServer(http.Dir(tt.rootDir))
			ts := httptest.NewServer(fs)
			defer ts.Close()

			tmpDir := t.TempDir()
			c := vulndb.NewVulnDB(vulndb.WithURL(ts.URL), vulndb.WithDir(tmpDir), vulndb.WithRetry(0))

			err := c.Update()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)

			for _, wantFile := range tt.wantFiles {
				got, err := os.ReadFile(filepath.Join(tmpDir, wantFile))
				require.NoError(t, err, tt.name)

				want, err := os.ReadFile(filepath.Join("testdata", "golden", filepath.Base(wantFile)))
				require.NoError(t, err, tt.name)

				assert.JSONEq(t, string(want), string(got))
			}
		})
	}
}
