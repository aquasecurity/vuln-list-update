package git_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vlgit "github.com/aquasecurity/vuln-list-update/git"
	"github.com/aquasecurity/vuln-list-update/utils"
)

// TestConfig_CloneOrPull clones once, guarding against a regression where cloning a single branch
// pulled the full history of every other branch too, then pulls into that same checkout: nothing
// exercised the pull path before, for any consumer of this package.
func TestConfig_CloneOrPull(t *testing.T) {
	remote := newTestRepo(t)

	dir := filepath.Join(t.TempDir(), "clone")
	_, err := (vlgit.Config{}).CloneOrPull(remote, dir, "master", false)
	require.NoError(t, err)

	t.Run("fetches only the requested branch", func(t *testing.T) {
		out := runGit(t, dir, "config", "remote.origin.fetch")
		assert.Equal(t, "+refs/heads/master:refs/remotes/origin/master", strings.TrimSpace(out))

		_, err := utils.Exec("git", []string{"-C", dir, "rev-parse", "--verify", "refs/remotes/origin/other"})
		assert.Error(t, err, "the unrequested branch must not have been fetched")
	})

	t.Run("pull picks up new commits", func(t *testing.T) {
		require.NoError(t, os.WriteFile(filepath.Join(remote, "new-file.txt"), []byte("new content"), 0o644))
		runGit(t, remote, "add", "new-file.txt")
		commit(t, remote, "add new-file.txt")

		updatedFiles, err := (vlgit.Config{}).CloneOrPull(remote, dir, "master", false)
		require.NoError(t, err)

		require.FileExists(t, filepath.Join(dir, "new-file.txt"))
		content, err := os.ReadFile(filepath.Join(dir, "new-file.txt"))
		require.NoError(t, err)
		assert.Equal(t, "new content", string(content))
		assert.Contains(t, updatedFiles, "new-file.txt")
	})
}

// newTestRepo creates a local repository with two branches of unrelated history, so a test can
// tell whether only the requested branch was fetched.
func newTestRepo(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	runGit(t, dir, "-c", "init.defaultBranch=master", "init", "--quiet")
	commit(t, dir, "master commit", "--allow-empty")
	runGit(t, dir, "checkout", "--quiet", "-b", "other")
	commit(t, dir, "other commit", "--allow-empty")
	runGit(t, dir, "checkout", "--quiet", "master")

	return dir
}

func commit(t *testing.T, dir, msg string, extraArgs ...string) {
	t.Helper()

	args := append([]string{"-c", "user.email=test@example.com", "-c", "user.name=test", "commit", "--quiet", "-m", msg}, extraArgs...)
	runGit(t, dir, args...)
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()

	out, err := utils.Exec("git", append([]string{"-C", dir}, args...))
	require.NoError(t, err)
	return out
}
