package git

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/knqyf263/vuln-list-update/utils"
	"golang.org/x/xerrors"
)

func CloneOrPull(url, repoPath string) (map[string]struct{}, error) {
	exists, err := utils.Exists(filepath.Join(repoPath, ".git"))
	if err != nil {
		return nil, err
	}

	updatedFiles := map[string]struct{}{}
	if exists {
		log.Println("git pull")
		files, err := pull(repoPath)
		if err != nil {
			return nil, xerrors.Errorf("git pull error: %w", err)
		}

		for _, filename := range files {
			updatedFiles[strings.TrimSpace(filename)] = struct{}{}
		}
	} else {
		if err = os.MkdirAll(repoPath, 0700); err != nil {
			return nil, err
		}
		if err := clone(url, repoPath); err != nil {
			return nil, err
		}

		err = filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
			if info.IsDir() {
				return nil
			}
			updatedFiles[path] = struct{}{}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return updatedFiles, nil
}

func clone(url, repoPath string) error {
	commandAndArgs := []string{"clone", url, repoPath}
	cmd := exec.Command("git", commandAndArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return xerrors.Errorf("failed to clone: %w", err)
	}
	return nil
}

func pull(repoPath string) ([]string, error) {
	commandArgs := generateGitArgs(repoPath)

	revParseCmd := []string{"rev-parse", "HEAD"}
	output, err := utils.Exec("git", append(commandArgs, revParseCmd...))
	if err != nil {
		return nil, xerrors.Errorf("error in git rev-parse: %w", err)
	}
	commitHash := strings.TrimSpace(output)

	pullCmd := []string{"pull", "origin", "master"}
	if _, err = utils.Exec("git", append(commandArgs, pullCmd...)); err != nil {
		return nil, xerrors.Errorf("error in git pull: %w", err)
	}

	fetchCmd := []string{"fetch", "--prune"}
	if _, err = utils.Exec("git", append(commandArgs, fetchCmd...)); err != nil {
		return nil, xerrors.Errorf("error in git fetch: %w", err)
	}

	diffCmd := []string{"diff", commitHash, "HEAD", "--name-only"}
	output, err = utils.Exec("git", append(commandArgs, diffCmd...))
	if err != nil {
		return nil, err
	}
	updatedFiles := strings.Split(strings.TrimSpace(output), "\n")
	return updatedFiles, nil
}

func Commit(repoPath, targetPath, message string) error {
	commandArgs := generateGitArgs(repoPath)
	addCmd := []string{"add", filepath.Join(repoPath, targetPath)}
	if _, err := utils.Exec("git", append(commandArgs, addCmd...)); err != nil {
		return xerrors.Errorf("error in git add: %w", err)
	}

	commitCmd := []string{"commit", "--message", message}
	if _, err := utils.Exec("git", append(commandArgs, commitCmd...)); err != nil {
		return xerrors.Errorf("error in git commit: %w", err)
	}

	return nil
}

func Push(repoPath, branch string) error {
	commandArgs := generateGitArgs(repoPath)
	pushCmd := []string{"push", "origin", branch}
	if _, err := utils.Exec("git", append(commandArgs, pushCmd...)); err != nil {
		return xerrors.Errorf("error in git push: %w", err)
	}
	return nil
}

func RemoteBranch(repoPath string) ([]string, error) {
	commandArgs := generateGitArgs(repoPath)
	branchCmd := []string{"branch", "--remote"}
	output, err := utils.Exec("git", append(commandArgs, branchCmd...))
	if err != nil {
		return nil, xerrors.Errorf("error in git branch: %w", err)
	}
	return strings.Split(output, "\n"), nil
}

func Checkout(repoPath string, branch string) error {
	commandArgs := generateGitArgs(repoPath)
	checkoutCmd := []string{"checkout", branch}
	_, err := utils.Exec("git", append(commandArgs, checkoutCmd...))
	if err != nil {
		return xerrors.Errorf("error in git checkout: %w", err)
	}
	return nil
}

func Status(repoPath string) ([]string, error) {
	commandArgs := generateGitArgs(repoPath)

	statusCmd := []string{"status", "--porcelain"}
	output, err := utils.Exec("git", append(commandArgs, statusCmd...))
	if err != nil {
		return nil, xerrors.Errorf("error in git status: %w", err)
	}
	return strings.Split(strings.TrimSpace(output), "\n"), nil
}

func DiffFile(repoPath string, hash, file string) ([]string, error) {
	commandArgs := generateGitArgs(repoPath)

	prevHash := fmt.Sprintf("%s^", hash)
	diffCmd := []string{"diff", "--unified=0", prevHash, hash, "--", file}
	output, err := utils.Exec("git", append(commandArgs, diffCmd...))
	if err != nil {
		return nil, xerrors.Errorf("error in git diff: %w", err)
	}
	return strings.Split(strings.TrimSpace(output), "\n"), nil
}

func DiffPrev(repoPath string, hash string) ([]string, error) {
	commandArgs := generateGitArgs(repoPath)

	prevHash := fmt.Sprintf("%s^", hash)
	diffCmd := []string{"diff", "--name-only", prevHash, hash, "--"}
	output, err := utils.Exec("git", append(commandArgs, diffCmd...))
	if err != nil {
		return nil, xerrors.Errorf("git diff previous commit: %w", err)
	}
	return strings.Split(output, "\n"), nil
}

func ShowFile(repoPath string, hash string, filename string) (string, error) {
	commandArgs := generateGitArgs(repoPath)

	showCmd := []string{"show", fmt.Sprintf("%s:%s", hash, filename)}
	output, err := utils.Exec("git", append(commandArgs, showCmd...))
	if err != nil {
		return "", xerrors.Errorf("git show: %w", err)
	}
	return output, nil
}

func generateGitArgs(repoPath string) []string {
	gitDir := filepath.Join(repoPath, ".git")
	return []string{"--git-dir", gitDir, "--work-tree", repoPath}
}
