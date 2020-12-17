package alpine

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	version "github.com/knqyf263/go-apk-version"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v2"

	"github.com/aquasecurity/vuln-list-update/git"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	alpineDir     = "alpine"
	defaultBranch = "master"
	repoURL       = "https://git.alpinelinux.org/aports/"
)

var (
	repoDir string

	// e.g. 4.8.0.-r1 => 4.8.0-r1
	malformedVerReplacer = strings.NewReplacer(".-", "-", ".r", "-r")
)

type Config struct {
	GitClient   git.Operations
	CacheDir    string
	VulnListDir string
}

func (c Config) Update() (err error) {
	log.Println("Fetching Alpine data...")
	repoDir = filepath.Join(c.CacheDir, "aports")
	if _, err = c.GitClient.CloneOrPull(repoURL, repoDir, defaultBranch); err != nil {
		return xerrors.Errorf("failed to clone alpine repository: %w", err)
	}

	// Extract secfixes in all APKBUILD
	log.Println("Extracting Alpine secfixes...")
	branches, err := c.GitClient.RemoteBranch(repoDir)
	if err != nil {
		return xerrors.Errorf("failed to show branches: %w", err)
	}

	// restore branch
	defer func() {
		if derr := c.GitClient.Checkout(repoDir, defaultBranch); derr != nil {
			log.Printf("checkout error: %s", derr)
		}
	}()

	for _, branch := range branches {
		branch = strings.TrimSpace(branch)
		if !strings.HasSuffix(branch, "-stable") {
			continue
		}
		s := strings.Split(branch, "/")
		if len(s) < 2 {
			continue
		}
		release := strings.TrimSuffix(s[1], "-stable")

		if err = c.GitClient.Checkout(repoDir, branch); err != nil {
			return xerrors.Errorf("git failed to checkout branch: %w", err)
		}

		advisories, err := c.walkApkBuild(repoDir, release)
		if err != nil {
			return xerrors.Errorf("failed to walk APKBUILD: %w", err)
		}

		log.Printf("Saving secfixes: %s\n", release)
		for _, advisory := range advisories {
			filePath, err := c.constructFilePath(advisory.Release, advisory.Repository, advisory.Package, advisory.VulnerabilityID)
			if err != nil {
				return xerrors.Errorf("failed to construct file path: %w", err)
			}

			ok, err := utils.Exists(filePath)
			if err != nil {
				return xerrors.Errorf("error in file existence check: %w", err)
			} else if ok && !c.shouldOverwrite(filePath, advisory.FixedVersion) {
				continue
			}

			if err = utils.Write(filePath, advisory); err != nil {
				return xerrors.Errorf("failed to write Alpine secfixes: %w", err)
			}
		}
	}

	return nil
}

func (c Config) shouldOverwrite(filePath string, currentVersion string) bool {
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()

	var advisory Advisory
	if err = json.NewDecoder(f).Decode(&advisory); err != nil {
		return true
	}
	if advisory.Package == "" || advisory.FixedVersion == "" {
		return true
	}
	// advisory with Subject is more accurate and should not be overwritten
	if advisory.Subject != "" {
		return false
	}

	prev, err := version.NewVersion(malformedVerReplacer.Replace(advisory.FixedVersion))
	if err != nil {
		log.Println(advisory.FixedVersion, err)
		return false
	}

	current, err := version.NewVersion(malformedVerReplacer.Replace(currentVersion))
	if err != nil {
		log.Println(currentVersion, err)
		return false
	}

	return current.LessThan(prev)
}

func (c Config) walkApkBuild(repoDir, release string) ([]Advisory, error) {
	var advisories []Advisory
	err := filepath.Walk(repoDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return xerrors.Errorf("file walk error: %w", err)
		}
		if info.IsDir() {
			return nil
		}

		// e.g. main/openssl/APKBUILD
		repo, pkg, filename := splitPath(path)
		if filename != "APKBUILD" || repo == "" || pkg == "" {
			return nil
		}

		content, err := ioutil.ReadFile(path)
		if err != nil {
			return xerrors.Errorf("file read error: %w", err)
		}

		secFixes, err := c.parseSecFixes(string(content))
		if err != nil {
			return err
		} else if secFixes == nil {
			return nil
		}

		advisories = append(advisories, c.buildAdvisories(secFixes, release, pkg, repo)...)
		return nil
	})

	if err != nil {
		return nil, xerrors.Errorf("failed to walk Alpine aport: %w", err)
	}
	return advisories, nil
}

func (c Config) buildAdvisories(secFixes map[string][]string, release string, pkg string, repo string) []Advisory {
	var advisories []Advisory
	for ver, vulnIDs := range secFixes {
		for _, vulnID := range vulnIDs {
			// Trim strings after a parenthesis
			// e.g. CVE-2017-2616 (+ regression fix)
			if index := strings.Index(vulnID, "("); index > 0 {
				vulnID = vulnID[:index]
			}

			// e.g. CVE-2016-9818 XSA-201
			for _, id := range strings.Fields(vulnID) {
				// e.g. CVE_2019-2426
				if strings.HasPrefix(id, "CVE_") {
					id = strings.ReplaceAll(id, "_", "-")
				}

				// reject invalid vulnerability IDs
				// e.g. CVE N/A
				if !strings.Contains(id, "-") {
					continue
				}
				advisory := Advisory{
					VulnerabilityID: id,
					Release:         release,
					Package:         pkg,
					Repository:      repo,
					FixedVersion:    ver,
				}
				advisories = append(advisories, advisory)
			}
		}
	}
	return advisories
}

func (c Config) constructFilePath(release, repository, pkg, cveID string) (string, error) {
	dir := filepath.Join(c.VulnListDir, alpineDir, release, repository, pkg)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return "", xerrors.Errorf("failed to create directory: %w", err)
	}

	return filepath.Join(dir, fmt.Sprintf("%s.json", cveID)), nil
}

func splitPath(filePath string) (string, string, string) {
	dir, base := filepath.Split(filePath)
	dir, pkg := filepath.Split(filepath.Clean(dir))
	repo := filepath.Base(filepath.Clean(dir))
	return filepath.Clean(repo), pkg, base
}

func (c Config) parsePkgVerRel(content string) (pkgVer string, pkgRel string, err error) {
	lines := strings.Split(content, "\n")

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "pkgver") {
			s := strings.Split(line, "=")
			if len(s) < 2 {
				return "", "", xerrors.Errorf("invalid pkgver: %s", line)
			}
			pkgVer = s[1]
		}

		if strings.HasPrefix(line, "pkgrel") {
			s := strings.Split(line, "=")
			if len(s) < 2 {
				return "", "", xerrors.Errorf("invalid pkgrel: %s", line)
			}
			pkgRel = s[1]
		}
	}
	return pkgVer, pkgRel, nil
}

func (c Config) parseSecFixes(content string) (secFixes map[string][]string, err error) {
	lines := strings.Split(content, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		//# secfixes:
		//#   2.4.11-r0:
		//#     - CVE-2018-19622
		//#   2.4.10-r0:
		//#     - CVE-2018-12086
		//#     - CVE-2018-18225
		if strings.HasPrefix(line, "# secfixes:") ||
			strings.HasPrefix(strings.ToLower(line), "# security fixes:") {
			// e.g. # secfixes:ss
			secfixesStr := "secfixes:"
			for i+1 < len(lines) && strings.HasPrefix(lines[i+1], "# ") {
				// Fix invalid yaml
				tmp := strings.TrimLeft(lines[i+1], "#")
				tmp = strings.TrimSpace(tmp)
				if !strings.HasPrefix(tmp, "-") && !strings.HasSuffix(tmp, ":") {
					lines[i+1] = lines[i+1] + ":"
				}

				// Fix invalid space
				if strings.HasSuffix(tmp, ":") {
					lines[i+1] = "  " + tmp
				} else if strings.HasPrefix(tmp, "-") {
					split := strings.Fields(tmp)
					lines[i+1] = "    " + strings.Join(split, " ")
				}

				secfixesStr += "\n" + strings.TrimPrefix(lines[i+1], "# ")
				i++
			}

			s := SecFixes{}
			if err := yaml.Unmarshal([]byte(secfixesStr), &s); err != nil {
				log.Printf("failed to unmarshal SecFixes: %s\n", err)
				return nil, nil
			}
			secFixes = s.SecFixes
		}
	}
	return secFixes, nil
}
