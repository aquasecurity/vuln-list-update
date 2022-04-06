package glad

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/afero"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v2"

	"github.com/aquasecurity/vuln-list-update/git"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	repoURL    = "https://gitlab.com/gitlab-org/advisories-community.git"
	repoBranch = "main"
	gladDir    = "glad" // GitLab Advisory Database
)

var (
	// https://gitlab.com/gitlab-org/advisories-community
	supportedTypes = []string{"gem", "go", "maven", "npm", "nuget", "packagist", "pypi", "nuget", "conan"}
)

type Updater struct {
	alternativeRepoBranch string
	alternativeRepoURL    string
	vulnListDir           string
	cacheDir              string
	appFs                 afero.Fs
}

func NewUpdater(alternativeRepoURL string, alternativeRepoBranch string) Updater {
	return Updater{
		alternativeRepoBranch: alternativeRepoBranch,
		alternativeRepoURL:    alternativeRepoURL,
		vulnListDir:           utils.VulnListDir(),
		cacheDir:              utils.CacheDir(),
		appFs:                 afero.NewOsFs(),
	}
}

func (u Updater) Update() error {
	log.Print("Fetching GitLab Advisory Database (advisories-community)")

	gc := git.Config{}
	dir := filepath.Join(u.cacheDir, gladDir)
	defaultOrAlternativeRepoURL := repoURL
	defaultOrAlternativeRepoBranch := repoBranch

	if len(u.alternativeRepoURL) > 0 {
		defaultOrAlternativeRepoURL = u.alternativeRepoURL
	}

	if len(u.alternativeRepoBranch) > 0 {
		defaultOrAlternativeRepoBranch = u.alternativeRepoBranch
	}

	if _, err := gc.CloneOrPull(defaultOrAlternativeRepoURL, dir, defaultOrAlternativeRepoBranch, false); err != nil {
		return xerrors.Errorf("failed to clone or pull: %w", err)
	}

	log.Println("Walking glad...")
	for _, target := range supportedTypes {
		targetDir := filepath.Join(dir, target)
		if ok, _ := utils.Exists(targetDir); !ok {
			continue
		}
		if err := u.walkDir(targetDir); err != nil {
			return xerrors.Errorf("failed to walk %s: %w", targetDir, err)
		}
	}

	return nil
}

func (u Updater) walkDir(root string) error {
	var advisories []advisory
	err := afero.Walk(u.appFs, root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return xerrors.Errorf("file walk error: %w", err)
		}
		if info.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		f, err := u.appFs.Open(path)
		if err != nil {
			return xerrors.Errorf("file open error (%s): %w", path, err)
		}
		defer f.Close()

		var adv advisory
		if err = yaml.NewDecoder(f).Decode(&adv); err != nil {
			return xerrors.Errorf("unable to decode YAML (%s): %w", path, err)
		}
		advisories = append(advisories, adv)

		return nil
	})
	if err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}

	for _, adv := range advisories {
		adv.PackageSlug = strings.TrimSuffix(adv.PackageSlug, "/")

		// Update Identifier to upper case
		// e.g. cvE-2014-3530 => CVE-2014-3530
		// https://gitlab.com/gitlab-org/advisories-community/-/blob/74a18a7968c2bdd2dd901f6c98f06cb1d9684476/maven/org.picketlink/picketlink-common/cvE-2014-3530.yml
		adv.Identifier = strings.ToUpper(adv.Identifier)

		slug := u.searchPrefix(adv, advisories)
		if slug != "" {
			// Update the package_slug to flatten nested packages
			// e.g.  go/k8s.io/kubernetes => go/k8s.io/kubernetes
			//       go/k8s.io/kubernetes/pkg/kubelet/kuberuntime => go/k8s.io/kubernetes
			adv.PackageSlug = slug
		}
		if err = u.save(adv); err != nil {
			return xerrors.Errorf("save error: %w", err)
		}
	}

	return nil
}

func (u Updater) searchPrefix(adv advisory, advisories []advisory) string {
	for _, a := range advisories {
		if a.PackageSlug == adv.PackageSlug {
			continue
		}

		if strings.HasPrefix(adv.PackageSlug, a.PackageSlug) {
			return a.PackageSlug
		}
	}
	return ""
}

func (u Updater) save(adv advisory) error {
	s := strings.Split(adv.PackageSlug, "/")
	dir := filepath.Join(s...)
	dir = filepath.Join(u.vulnListDir, gladDir, dir)

	fileName := fmt.Sprintf("%s.json", adv.Identifier)
	if err := utils.WriteJSON(u.appFs, dir, fileName, adv); err != nil {
		return xerrors.Errorf("unable to write JSON (%s): %w", fileName, err)
	}
	return nil
}
