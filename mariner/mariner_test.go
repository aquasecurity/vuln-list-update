package mariner_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/mariner"
)

func TestUpdate(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "file::testdata/happy",
		},
		{
			name:      "sad path, invalid xml",
			inputFile: "file::testdata/sad",
			wantErr:   "failed to decode xml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			cc := mariner.NewConfig(mariner.WithURL(tt.inputFile), mariner.WithDir(tmpDir), mariner.WithRetry(0))

			err := cc.Update()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)

			err = filepath.WalkDir(tmpDir, func(path string, d fs.DirEntry, err error) error {
				require.NoError(t, err, tt.name)
				if !d.Type().IsRegular() {
					return nil
				}

				got, err := os.ReadFile(path)
				require.NoError(t, err, path)

				rel, err := filepath.Rel(tmpDir, path)
				require.NoError(t, err, path)

				goldenPath := filepath.Join("testdata", "golden", "mariner", rel)
				want, err := os.ReadFile(goldenPath)
				require.NoError(t, err, goldenPath)

				assert.JSONEq(t, string(want), string(got), path)

				return nil
			})
			require.NoError(t, err, tt.name)
		})
	}
}
