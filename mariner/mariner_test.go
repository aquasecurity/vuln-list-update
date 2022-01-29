package mariner_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	mariner "github.com/aquasecurity/vuln-list-update/mariner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdate(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		wantError string
	}{
		{
			name:      "happy path",
			inputFile: "file::testdata/happy",
			wantError: "",
		},
		{
			name:      "sad path, invalid xml",
			inputFile: "file::testdata/sad/invalid",
			wantError: "failed to update oval data: failed to decode xml: XML syntax error on line 80: unexpected EOF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			cc := mariner.NewConfig(mariner.WithURLs(tt.inputFile), mariner.WithDir(tmpDir), mariner.WithRetry(0))
			if err := cc.Update(); tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
				return
			}

			fsys := os.DirFS(tmpDir)
			err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
				if !d.Type().IsRegular() {
					return nil
				}
				assert.NoError(t, err, tt.name)

				got, err := os.ReadFile(filepath.Join(tmpDir, path))
				assert.NoError(t, err, tt.name)

				goldenPath := filepath.Join("testdata", "golden", "mariner", path)
				want, err := os.ReadFile(goldenPath)
				assert.NoError(t, err, tt.name)

				assert.JSONEq(t, string(want), string(got), path)

				return nil
			})
			assert.Nil(t, err, "filepath walk error")
		})
	}
}
