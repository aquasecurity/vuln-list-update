package k8s

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/git"
	"github.com/aquasecurity/vuln-list-update/osv"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	repoURL     = "https://github.com/kubernetes-sigs/cve-feed-osv.git"
	repoBranch  = "main"
	upstreamDir = "upstream" // k8s upstream Advisory Database
)

type Updater struct {
	vulnListDir string
	cacheDir    string
	appFs       afero.Fs
}

func NewUpdater() Updater {
	return Updater{
		vulnListDir: utils.VulnListDir(),
		cacheDir:    utils.CacheDir(),
		appFs:       afero.NewOsFs(),
	}
}

func (u Updater) Update() error {
	log.Print("Fetching k8s upstream Advisory Database")

	gc := git.Config{}
	dir := filepath.Join(u.cacheDir, upstreamDir)
	if _, err := gc.CloneOrPull(repoURL, dir, repoBranch, false); err != nil {
		return xerrors.Errorf("failed to clone or pull: %w", err)
	}

	log.Println("Removing old k8s upstream files...")
	if err := os.RemoveAll(filepath.Join(u.vulnListDir, upstreamDir)); err != nil {
		return xerrors.Errorf("can't remove a folder with old files %s/%s: %w", u.vulnListDir, upstreamDir, err)
	}

	log.Println("Walking k8s upstream...")

	targetDir := filepath.Join(dir, "vulns")
	if ok, _ := utils.Exists(targetDir); !ok {
		return xerrors.Errorf("directory not found: %s", targetDir)
	}
	if err := u.walkDir(targetDir); err != nil {
		return xerrors.Errorf("failed to walk %s: %w", targetDir, err)

	}

	return nil
}

func (u Updater) walkDir(root string) error {
	var advisories []osv.OSV
	err := afero.Walk(u.appFs, root, func(path string, info os.FileInfo, err error) error {
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

		f, err := u.appFs.Open(path)
		if err != nil {
			return xerrors.Errorf("file open error (%s): %w", path, err)
		}
		defer f.Close()

		var adv osv.OSV
		if err = json.NewDecoder(f).Decode(&adv); err != nil {
			return xerrors.Errorf("unable to decode JSON (%s): %w", path, err)
		}
		advisories = append(advisories, adv)

		return nil
	})
	if err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}

	for _, adv := range advisories {
		if err = u.save(adv); err != nil {
			return xerrors.Errorf("save error: %w", err)
		}
	}

	return nil
}

func (u Updater) save(osv osv.OSV) error {
	dir := filepath.Join(u.vulnListDir, upstreamDir)
	fileName := fmt.Sprintf("%s.json", osv.ID)
	if err := utils.WriteJSON(u.appFs, dir, fileName, osv); err != nil {
		return xerrors.Errorf("unable to write JSON (%s): %w", fileName, err)
	}
	return nil
}
