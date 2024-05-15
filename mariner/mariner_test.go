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

func TestAdvisoryID(t *testing.T) {
	tests := []struct {
		name string
		def  mariner.Definition
		want string
	}{
		{
			name: "advisory_id without version",
			def: mariner.Definition{
				Metadata: mariner.Metadata{
					AdvisoryID: "1111",
				},
			},
			want: "1111",
		},
		{
			name: "advisory_id with version",
			def: mariner.Definition{
				Metadata: mariner.Metadata{
					AdvisoryID: "1111-2",
				},
			},
			want: "1111-2",
		},
		{
			name: "build advisoryID converting long version to 1",
			def: mariner.Definition{
				ID:      "oval:com.microsoft.cbl-mariner:def:27423",
				Version: "2000000001",
			},
			want: "27423-1",
		},
		{
			name: "build advisoryID converting long version to 0",
			def: mariner.Definition{
				ID:      "oval:com.microsoft.cbl-mariner:def:27423",
				Version: "2000000000",
			},
			want: "27423",
		},
		{
			name: "build advisoryID with short 1 version",
			def: mariner.Definition{
				ID:      "oval:com.microsoft.cbl-mariner:def:27423",
				Version: "1",
			},
			want: "27423-1",
		},
		{
			name: "build advisoryID with short 0 version",
			def: mariner.Definition{
				ID:      "oval:com.microsoft.cbl-mariner:def:27423",
				Version: "0",
			},
			want: "27423",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mariner.AdvisoryID(tt.def)
			require.Equal(t, tt.want, got)
		})
	}
}
