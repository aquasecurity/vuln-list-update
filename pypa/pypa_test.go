package pypa

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Update(t *testing.T) {
	tests := []struct {
		name          string
		inputArchive  string
		expectedFiles []string
		wantErr       string
	}{
		{
			name:          "happy path",
			inputArchive:  "testdata/pypa.zip",
			expectedFiles: []string{"PYSEC-2005-1.json", "PYSEC-2006-1.json", "PYSEC-2006-2.json"},
		},
		{
			name:    "sad path, unable to download archive",
			wantErr: "connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, err := os.ReadFile(tt.inputArchive)
				require.NoError(t, err)

				w.Write(b)
			}))

			defer ts.Close()

			// Intentionally close to induce network errors
			if tt.inputArchive == "" {
				ts.Close()
			}

			dir := t.TempDir()
			c := NewPypa(WithURL(ts.URL+"/"+tt.inputArchive), WithDir(filepath.Join(dir)), WithRetry(0))
			err := c.Update()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}

			entries, err := os.ReadDir("testdata/golden")
			require.NoError(t, err)

			for _, e := range entries {
				if e.IsDir() {
					continue
				}

				filePath := e.Name()
				gotJSON, err := os.ReadFile(filepath.Join(dir, filePath))
				require.NoError(t, err)

				wantJSON, err := os.ReadFile(filepath.Join("testdata", "golden", filepath.Base(filePath)))
				require.NoError(t, err)

				assert.JSONEq(t, string(wantJSON), string(gotJSON))
			}
		})
	}
}
