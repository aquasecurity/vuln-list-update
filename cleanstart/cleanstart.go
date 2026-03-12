package cleanstart

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/git"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	cleanstartDir = "cleanstart"
	advisoriesDir = "advisories"
	repoURL       = "https://github.com/cleanstart-dev/cleanstart-security-advisories"
	repoBranch    = "main"
)

type option func(c *Updater)

func WithVulnListDir(v string) option {
	return func(c *Updater) { c.vulnListDir = v }
}

func WithRepoURL(v string) option {
	return func(c *Updater) { c.repoURL = v }
}

type Updater struct {
	vulnListDir string
	repoURL     string
	git         git.Config
}

func NewUpdater(options ...option) *Updater {
	updater := &Updater{
		vulnListDir: utils.VulnListDir(),
		repoURL:     repoURL,
		git:         git.Config{},
	}
	for _, option := range options {
		option(updater)
	}
	return updater
}

func (u *Updater) Update() error {
	repoPath := filepath.Join(utils.CacheDir(), cleanstartDir)
	log.Printf("Cloning/pulling CleanStart advisories from %s into %s", u.repoURL, repoPath)
	_, err := u.git.CloneOrPull(u.repoURL, repoPath, repoBranch, false)
	if err != nil {
		return xerrors.Errorf("failed to clone/pull CleanStart advisories: %w", err)
	}

	outDir := filepath.Join(u.vulnListDir, cleanstartDir, advisoriesDir)
	log.Printf("Removing CleanStart output directory %s", outDir)
	if err := os.RemoveAll(outDir); err != nil {
		return xerrors.Errorf("failed to remove CleanStart directory: %w", err)
	}

	srcDir := filepath.Join(repoPath, advisoriesDir)
	log.Printf("Walking CleanStart advisories from %s", srcDir)
	err = filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return xerrors.Errorf("failed to read advisory %s: %w", path, err)
		}

		var raw map[string]interface{}
		if err := json.Unmarshal(data, &raw); err != nil {
			return xerrors.Errorf("invalid JSON in advisory %s: %w", path, err)
		}

		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return xerrors.Errorf("failed to get relative path: %w", err)
		}
		destPath := filepath.Join(outDir, rel)

		if err := utils.Write(destPath, raw); err != nil {
			return xerrors.Errorf("failed to write advisory %s: %w", destPath, err)
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("failed to walk CleanStart advisories: %w", err)
	}

	log.Printf("CleanStart advisories updated successfully in %s", outDir)
	return nil
}