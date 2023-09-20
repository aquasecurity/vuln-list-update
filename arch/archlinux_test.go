package arch_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/arch"
)

func TestUpdate(t *testing.T) {
	tests := []struct {
		name          string
		inputJSONFile string
		wantErr       string
	}{
		{
			name:          "happy path",
			inputJSONFile: "testdata/archlinux.json",
		},
		{
			name:    "sad path, unreachable Arch Linux service",
			wantErr: "connection refused",
		},
		{
			name:          "sad path, invalid json",
			inputJSONFile: "testdata/invalid.json",
			wantErr:       "json unmarshal error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, err := os.ReadFile(tt.inputJSONFile)
				require.NoError(t, err)

				_, _ = io.WriteString(w, string(b))
			}))
			defer ts.Close()

			// Intentionally close to induce network errors
			if tt.inputJSONFile == "" {
				ts.Close()
			}

			dir := t.TempDir()
			c := arch.NewArchLinux(arch.WithURL(ts.URL), arch.WithDir(filepath.Join(dir)), arch.WithRetry(0))
			err := c.Update()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			entries, err := os.ReadDir(dir)
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
