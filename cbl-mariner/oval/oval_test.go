package oval_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	cblmariner "github.com/aquasecurity/vuln-list-update/cbl-mariner/oval"
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
			wantError: "failed to walk directory: failed to update oval data: failed to unmarshal xml: XML syntax error on line 80: unexpected EOF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			cc := cblmariner.NewConfig(cblmariner.WithURLs(tt.inputFile), cblmariner.WithDir(tmpDir), cblmariner.WithRetry(0))
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

				goldenPath := filepath.Join("testdata", "golden", "cbl-mariner", "oval", path)
				want, err := os.ReadFile(goldenPath)
				assert.NoError(t, err, tt.name)

				assert.JSONEq(t, string(want), string(got), path)

				return nil
			})
			assert.Nil(t, err, "filepath walk error")
		})
	}
}
