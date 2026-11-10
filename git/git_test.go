package git_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	vlgit "github.com/aquasecurity/vuln-list-update/git"
)

// TestConfig_CloneOrPull_FetchesOnlyTheRequestedBranch guards against a regression where cloning
// a single branch pulled the full history of every other branch in the repository too.
func TestConfig_CloneOrPull_FetchesOnlyTheRequestedBranch(t *testing.T) {
	remote := newTestRepo(t)

	dir := filepath.Join(t.TempDir(), "clone")
	_, err := (vlgit.Config{}).CloneOrPull(remote, dir, "master", false)
	require.NoError(t, err)

	out := runGit(t, dir, "config", "remote.origin.fetch")
	assert.Equal(t, "+refs/heads/master:refs/remotes/origin/master", strings.TrimSpace(out))

	err = exec.Command("git", "--git-dir", filepath.Join(dir, ".git"), "rev-parse", "--verify", "refs/remotes/origin/other").Run()
	assert.Error(t, err, "the unrequested branch must not have been fetched")
}

// TestConfig_CloneOrPull_Pull covers the second call against an already-cloned shallow,
// single-branch checkout: nothing exercised this path before, for any consumer of this package.
func TestConfig_CloneOrPull_Pull(t *testing.T) {
	remote := newTestRepo(t)

	dir := filepath.Join(t.TempDir(), "clone")
	_, err := (vlgit.Config{}).CloneOrPull(remote, dir, "master", false)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(remote, "new-file.txt"), []byte("new content"), 0o644))
	runGit(t, remote, "add", "new-file.txt")
	cmd := exec.Command("git", "-c", "user.email=test@example.com", "-c", "user.name=test",
		"commit", "--quiet", "-m", "add new-file.txt")
	cmd.Dir = remote
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	updatedFiles, err := (vlgit.Config{}).CloneOrPull(remote, dir, "master", false)
	require.NoError(t, err)

	require.FileExists(t, filepath.Join(dir, "new-file.txt"))
	content, err := os.ReadFile(filepath.Join(dir, "new-file.txt"))
	require.NoError(t, err)
	assert.Equal(t, "new content", string(content))
	assert.Contains(t, updatedFiles, "new-file.txt")
}

// newTestRepo creates a local repository with two branches of unrelated history, so a test can
// tell whether only the requested branch was fetched.
func newTestRepo(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	runGit(t, dir, "-c", "init.defaultBranch=master", "init", "--quiet")
	commit := func(msg string) {
		cmd := exec.Command("git", "-c", "user.email=test@example.com", "-c", "user.name=test",
			"commit", "--allow-empty", "--quiet", "-m", msg)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
	}
	commit("master commit")
	runGit(t, dir, "checkout", "--quiet", "-b", "other")
	commit("other commit")
	runGit(t, dir, "checkout", "--quiet", "master")

	return dir
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	return string(out)
}
