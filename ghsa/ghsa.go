package ghsa

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/vuln-list-update/git"
	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// ecosystems is list of ecosystems
// name from file -> name of folder
var ecosystems = map[Ecosystem]string{
	"Packagist": "composer",
	"Hex":       "erlang",
	"go":        "Go",
	"Maven":     "maven",
	"npm":       "npm",
	"NuGet":     "nuget",
	"PyPI":      "pip",
	"Pub":       "pub",
	"RubyGems":  "rubygems",
	"crates.io": "rust",
}

const (
	ghsaDir         = "ghsa"
	ghsaReviewedDir = "advisories/github-reviewed"
	repoURL         = "https://github.com/github/advisory-database.git"
	repoBranch      = "main"
)

type Config struct {
	vulnListDir           string
	cacheDir              string
	alternativeRepoBranch string
	alternativeRepoURL    string
	appFs                 afero.Fs
}

type GithubClient interface {
	Query(ctx context.Context, q interface{}, variables map[string]interface{}) error
}

func NewConfig(alternativeRepoURL string, alternativeRepoBranch string) Config {
	return Config{
		vulnListDir:           utils.VulnListDir(),
		cacheDir:              utils.CacheDir(),
		alternativeRepoBranch: alternativeRepoBranch,
		alternativeRepoURL:    alternativeRepoURL,
		appFs:                 afero.NewOsFs(),
	}
}

func (c Config) Update() error {
	log.Print("Fetching GitHub Security Advisory")

	gc := git.Config{}
	dir := filepath.Join(c.cacheDir, ghsaDir)
	defaultOrAlternativeRepoURL := repoURL
	defaultOrAlternativeRepoBranch := repoBranch

	if len(c.alternativeRepoURL) > 0 {
		defaultOrAlternativeRepoURL = c.alternativeRepoURL
	}

	if len(c.alternativeRepoBranch) > 0 {
		defaultOrAlternativeRepoBranch = c.alternativeRepoBranch
	}

	if _, err := gc.CloneOrPull(defaultOrAlternativeRepoURL, dir, defaultOrAlternativeRepoBranch, false); err != nil {
		return xerrors.Errorf("failed to clone or pull: %w", err)
	}

	log.Println("Removing old ghsa files...")
	if err := os.RemoveAll(filepath.Join(c.vulnListDir, ghsaDir)); err != nil {
		return xerrors.Errorf("can't remove a folder with old files %s/%s: %w", c.vulnListDir, ghsaDir, err)
	}

	log.Println("Walking ghsa...")

	if err := c.walkDir(dir); err != nil {
		return xerrors.Errorf("failed to walk %s: %w", dir, err)
	}

	return nil
}

func (c Config) walkDir(ghsaDir string) error {
	reviewedDir := filepath.Join(ghsaDir, ghsaReviewedDir)
	err := afero.Walk(c.appFs, reviewedDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return xerrors.Errorf("file walk error: %w", err)
		}
		if info.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		if ext != ".json" {
			return nil
		}

		f, err := c.appFs.Open(path)
		if err != nil {
			return xerrors.Errorf("file open error (%s): %w", path, err)
		}
		defer f.Close()

		var entry Entry
		if err = json.NewDecoder(f).Decode(&entry); err != nil {
			return xerrors.Errorf("unable to decode JSON (%s): %w", path, err)
		}
		err = c.saveGSHA(ghsaDir, entry)
		if err != nil {
			return xerrors.Errorf("unable to save advisory (%s): %w", path, err)
		}

		return nil
	})
	if err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}

	return nil
}

func (c Config) saveGSHA(_ string, entry Entry) error {
	uniqPkgName := map[string]struct{}{}
	for _, pkg := range entry.Affected {
		name := pkg.Module.Path
		if pkg.Module.Ecosystem == "Maven" {
			name = strings.ReplaceAll(pkg.Module.Path, ":", "/")
		}
		if ecosystemDir, ok := ecosystems[pkg.Module.Ecosystem]; ok {
			if _, ok := uniqPkgName[name]; !ok {
				fileName := fmt.Sprintf("%s.json", entry.ID)
				dir := filepath.Join(c.vulnListDir, ghsaDir, ecosystemDir, name)
				if err := utils.WriteJSON(c.appFs, dir, fileName, entry); err != nil {
					return xerrors.Errorf("failed to write file: %w", err)
				}
				uniqPkgName[name] = struct{}{}
			}
		}
	}
	return nil
}
