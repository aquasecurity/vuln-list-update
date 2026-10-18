package cleanstart_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/cleanstart"
)

// initRepo creates a git repository holding the given files, keyed by their path
// relative to the repository root, and returns its path. The updater clones the
// advisory repository, so a local repository exercises that path without network
// access.
func initRepo(t *testing.T, files map[string]string) string {
	t.Helper()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}

	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}

	for _, args := range [][]string{
		{"init", "-b", "main"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "test"},
		{"add", "."},
		{"commit", "-m", "advisories"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		require.NoErrorf(t, err, "git %v: %s", args, out)
	}
	return dir
}

func TestUpdater_Update(t *testing.T) {
	advisory, err := os.ReadFile(filepath.Join("testdata", "advisories", "2025", "CLEANSTART-2025-CN65903.json"))
	require.NoError(t, err)

	t.Run("happy path", func(t *testing.T) {
		repoDir := initRepo(t, map[string]string{
			"advisories/2025/CLEANSTART-2025-CN65903.json": string(advisory),
			"advisories/README.md":                         "not an advisory",
		})
		vulnListDir := t.TempDir()

		// An advisory left over from an earlier run that is no longer published.
		stale := filepath.Join(vulnListDir, "cleanstart", "advisories", "2024", "CLEANSTART-2024-STALE.json")
		require.NoError(t, os.MkdirAll(filepath.Dir(stale), 0o755))
		require.NoError(t, os.WriteFile(stale, []byte("{}"), 0o644))

		u := cleanstart.NewUpdater(
			cleanstart.WithRepoURL(repoDir),
			cleanstart.WithCacheDir(t.TempDir()),
			cleanstart.WithVulnListDir(vulnListDir),
		)
		require.NoError(t, u.Update())

		// Advisories are copied into vuln-list, keeping the year directory layout
		// that trivy-db walks.
		got, err := os.ReadFile(filepath.Join(vulnListDir, "cleanstart", "advisories", "2025", "CLEANSTART-2025-CN65903.json"))
		require.NoError(t, err)

		// The advisory is re-indented on the way out, so compare the decoded content
		// rather than the bytes.
		assert.JSONEq(t, string(advisory), string(got))

		// Only JSON is copied; anything else in the repository is left behind.
		assert.NoFileExists(t, filepath.Join(vulnListDir, "cleanstart", "advisories", "README.md"))

		// The output directory is rebuilt from scratch, so withdrawn advisories do not
		// linger in vuln-list after they disappear upstream.
		assert.NoFileExists(t, stale)
	})

	t.Run("invalid advisory", func(t *testing.T) {
		repoDir := initRepo(t, map[string]string{
			"advisories/2025/CLEANSTART-2025-BROKEN.json": "{not json",
		})

		u := cleanstart.NewUpdater(
			cleanstart.WithRepoURL(repoDir),
			cleanstart.WithCacheDir(t.TempDir()),
			cleanstart.WithVulnListDir(t.TempDir()),
		)
		require.ErrorContains(t, u.Update(), "invalid JSON in advisory")
	})
}
