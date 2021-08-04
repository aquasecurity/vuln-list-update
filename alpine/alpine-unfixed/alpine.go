package alpineunfix

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"path"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	alpineDir          = "alpine-unfixed"
	baseUrl            = "https://security.alpinelinux.org"
	retry              = 3
	OsPackageSeparator = "||"
)

var (
	alpineActiveReleases = []string{
		"edge-main",
		"edge-community",
		"3.14-main",
		"3.14-community",
		"3.13-main",
		"3.12-main",
		"3.11-main",
		"3.10-main",
	}
)

type Updater struct {
	vulnListDir    string
	appFs          afero.Fs
	baseURL        string
	retry          int
	CVEUrl         string
	activeReleases []string
}

func NewUpdater() *Updater {
	updater := &Updater{
		vulnListDir:    utils.VulnListDir(),
		appFs:          afero.NewOsFs(),
		baseURL:        baseUrl,
		retry:          retry,
		activeReleases: alpineActiveReleases,
	}
	return updater
}
func (u Updater) Update() (err error) {
	baseData := make(map[string]string)
	dir := filepath.Join(u.vulnListDir, alpineDir)
	log.Printf("Remove Alpine directory %s", dir)
	if err := u.appFs.RemoveAll(dir); err != nil {
		return xerrors.Errorf("failed to remove Alpine directory: %w", err)
	}
	if err := u.appFs.MkdirAll(dir, 0755); err != nil {
		return xerrors.Errorf("Failed creating dir %s: %w", dir, err)
	}

	log.Println("Fetching branch data...")
	for _, branch := range u.activeReleases {
		log.Println("Processing::", branch)
		branchPath := utils.JoinURL(u.baseURL, "branch", branch)
		if err := parseBranchVulnerabilities(branchPath, branch, baseData, u.baseURL); err != nil {
			return xerrors.Errorf("Failed parsing branch %s: %w", branchPath, err)
		}

		orphanedVulnPkgs := utils.JoinURL(branchPath, "vuln-orphaned")
		if err = parseBranchVulnerabilities(orphanedVulnPkgs, branch, baseData, u.baseURL); err != nil {
			return xerrors.Errorf("Failed parsing branch %s: %w", orphanedVulnPkgs, err)
		}
	}
	log.Println("Done Processing")
	branchPkgMap := make(map[string]VulnVersionMap)
	for key, version := range baseData {
		packageData := strings.Split(key, ":")
		branchPkg := packageData[0]
		vulnerability := packageData[1]
		if vulnVersion, exists := branchPkgMap[branchPkg]; exists {
			if vulns, ok := vulnVersion[version]; ok {
				vulns = append(vulns, vulnerability)
				vulnVersion[version] = vulns
			} else {
				vulns = []string{vulnerability}
				vulnVersion[version] = vulns
			}

		} else {
			vulns := []string{vulnerability}
			branchPkgMap[branchPkg] = VulnVersionMap{version: vulns}
		}
	}
	return u.save(branchPkgMap)
}

func (u Updater) save(packageData map[string]VulnVersionMap) error {
	for branchPkg, vulnData := range packageData {
		branchPkgDet := strings.Split(branchPkg, OsPackageSeparator)
		branch := strings.Split(branchPkgDet[0], "-")
		release := branch[0]
		repoName := branch[1]
		packageName := branchPkgDet[1]
		dir := filepath.Join(u.vulnListDir, alpineDir, release, repoName)
		file := fmt.Sprintf("%s.json", packageName)
		saveJson := SaveJsonFormat{
			DistroVersion: fmt.Sprintf("v%s", release),
			RepoName:      repoName,
			UnfixVersion:  vulnData,
			PkgName:       packageName,
		}
		if err := utils.WriteJSON(u.appFs, dir, file, saveJson); err != nil {
			return xerrors.Errorf("failed to write %s under %s: %w", file, dir, err)
		}
	}
	return nil
}

func parseBranchVulnerabilities(branchPath, branch string, baseData map[string]string, baseUrl string) error {

	b, err := utils.FetchURLWithHeaders(branchPath, map[string]string{"accept": "application/ld+json"})
	if err != nil {
		return err
	}
	var releaseInfo ReleaseInfo
	if err = json.Unmarshal(b, &releaseInfo); err != nil {
		return err
	}
	for _, item := range releaseInfo.Items {
		_, packageName := path.Split(item.CPEMatch[0].Package)
		_, vulnerability := path.Split(item.CPEMatch[0].Vulnerability)
		key := fmt.Sprintf("%s%s%s:%s", branch, OsPackageSeparator, packageName, vulnerability)
		if _, exists := baseData[key]; !exists {
			err := cveHTMLParser(baseUrl, vulnerability, baseData)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func cveHTMLParser(baseUrl, vulnerability string, baseData map[string]string) error {
	cveUrl := utils.JoinURL(baseUrl, "vuln", vulnerability)
	b, err := utils.FetchURLWithHeaders(cveUrl, map[string]string{"accept": "text/html"})
	if err != nil {
		return err
	}
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(b))
	if err != nil {
		return err
	}
	doc.Find(".state-unfixed").Each(func(i int, selection *goquery.Selection) {
		pkgData := selection.Text()
		if pkgData != "" {
			rawPkgData := strings.Split(pkgData, "\n")
			if len(rawPkgData) == 7 {
				os := strings.Trim(rawPkgData[2], " ")
				fixed := strings.Trim(rawPkgData[5], " ")
				if fixed == "possibly vulnerable" {
					packageName := strings.Trim(rawPkgData[1], " ")
					key := fmt.Sprintf("%s%s%s:%s", os, OsPackageSeparator, packageName, vulnerability)
					if _, exists := baseData[key]; !exists {
						baseData[key] = strings.Trim(rawPkgData[3], " ")
					}
					return
				}
			}
		}
	})
	return nil
}
