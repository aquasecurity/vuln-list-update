package rapidfort

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "update golden files")

func TestUpdater_Update(t *testing.T) {
	tests := []struct {
		name          string
		repoDir       string
		supportedOSes []string
		wantErr       string
		wantFiles     []string // relative paths under tmpDir/rapidfort that should exist
		wantNoFiles   []string // relative paths that must NOT exist
	}{
		{
			name:          "happy path — ubuntu, redhat, alpine with multiple versions",
			repoDir:       "testdata/repo",
			supportedOSes: []string{"ubuntu", "redhat", "alpine"},
			wantFiles: []string{
				"ubuntu/20.04/curl.json",
				"redhat/9/curl.json",
				"alpine/3.18/curl.json",
				"alpine/3.19/curl.json",
			},
		},
		{
			name:          "invalid JSON is skipped without error",
			repoDir:       "testdata/repo_invalid",
			supportedOSes: []string{"ubuntu"},
		},
		{
			name:          "missing OS directory is skipped without error",
			repoDir:       "testdata/repo_empty",
			supportedOSes: []string{"ubuntu"},
		},
		{
			name:          "missing package_name is skipped without error",
			repoDir:       "testdata/repo_missing_pkgname",
			supportedOSes: []string{"ubuntu"},
			wantNoFiles:   []string{"ubuntu/20.04/curl.json"},
		},
		{
			name:          "empty advisory map produces no output file",
			repoDir:       "testdata/repo_empty_advisory",
			supportedOSes: []string{"ubuntu"},
			wantNoFiles:   []string{"ubuntu/20.04/curl.json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			updater := NewUpdater(
				WithVulnListDir(tmpDir),
				WithRepoDir(tt.repoDir),
				WithSupportedOSes(tt.supportedOSes),
			)

			err := updater.Update()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			for _, relPath := range tt.wantFiles {
				actualPath := filepath.Join(tmpDir, rapidfortDir, relPath)
				actual, err := os.ReadFile(actualPath)
				require.NoError(t, err, "expected output file not found: %s", relPath)

				goldenPath := filepath.Join("testdata", "happy", relPath)
				if *update {
					require.NoError(t, os.MkdirAll(filepath.Dir(goldenPath), 0755))
					require.NoError(t, os.WriteFile(goldenPath, actual, 0644))
				}

				expected, err := os.ReadFile(goldenPath)
				require.NoError(t, err, "golden file not found: %s", goldenPath)

				assert.JSONEq(t, string(expected), string(actual), "mismatch for %s", relPath)
			}

			for _, relPath := range tt.wantNoFiles {
				absentPath := filepath.Join(tmpDir, rapidfortDir, relPath)
				_, err := os.Stat(absentPath)
				assert.True(t, os.IsNotExist(err), "file should not exist but does: %s", relPath)
			}
		})
	}
}
