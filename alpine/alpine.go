package alpine

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	pb "gopkg.in/cheggaaa/pb.v1"

	"gopkg.in/yaml.v2"

	version "github.com/hashicorp/go-version"
	"github.com/aquasecurity/vuln-list-update/git"
	"github.com/aquasecurity/vuln-list-update/utils"
	"golang.org/x/xerrors"
)

const (
	dist            = "alpine"
	alpineDir       = "alpine"
	repoURL         = "https://git.alpinelinux.org/aports/"
	trackerEndpoint = "https://bugs.alpinelinux.org"
	trackerListPath = "projects/alpine/issues.json"
	limit           = "100"
	concurrency     = 10
	wait            = 3
	retry           = 5
)

var (
	cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	repoDir      string

	// e.g.
	//   - 9.12.1_p2-r0 => 9.12.1-p2-r0
	//   - 4.8.0.-r1 => 4.8.0-r1
	malformedVerReplacer = strings.NewReplacer("_p", "-p", ".-", "-", ".r", "-r", "_alpha", "-alpha", "_rc", "-rc")
)

func Update() (err error) {
	log.Println("Fetching Alpine data...")
	repoDir = filepath.Join(utils.CacheDir(), "aports")
	if _, err = git.CloneOrPull(repoURL, repoDir); err != nil {
		return xerrors.Errorf("failed to clone alpine repository: %w", err)
	}

	//lastUpdated, err := utils.GetLastUpdatedDate(dist)
	//if err != nil {
	//	return xerrors.Errorf("failed to get last updated date: %w", err)
	//}
	//
	//log.Println("Fetching Alpine Security Issues...")
	//var issueURLs []string
	//for _, statusID := range []int{3, 5} {
	//	for page := 1; ; page++ {
	//		log.Printf("status_id: %d, page %d\n", statusID, page)
	//		url := constructListURL(statusID, page, lastUpdated)
	//		res, err := utils.FetchURL(url, "", retry)
	//		if err != nil {
	//			return xerrors.Errorf("failed to fetch Alpine issues: %w", err)
	//		}
	//		tracker := IssueList{}
	//		if err = json.Unmarshal(res, &tracker); err != nil {
	//			return err
	//		}
	//		if len(tracker.Issues) == 0 {
	//			break
	//		}
	//
	//		for _, issue := range tracker.Issues {
	//			if strings.Index(issue.Subject, "(") < 0 {
	//				continue
	//			}
	//			issueURLs = append(issueURLs, constructDetailURL(issue.ID))
	//		}
	//	}
	//}
	//
	//if len(issueURLs) == 0 {
	//	log.Println("No updated issue")
	//} else {
	//	if err = retrieveIssue(issueURLs); err != nil {
	//		return err
	//	}
	//}

	// Extract secfixes in all APKBUILD
	log.Println("Extracting Alpine secfixes...")
	branches, err := git.RemoteBranch(repoDir)
	if err != nil {
		return xerrors.Errorf("failed to show branches: %w", err)
	}

	defer func() {
		// restore branch
		if err = git.Checkout(repoDir, "master"); err != nil {
			err = xerrors.Errorf("error in git checkout: %w", err)
		}
	}()

	for _, branch := range branches {
		branch = strings.TrimSpace(branch)
		if !strings.HasSuffix(branch, "-stable") {
			continue
		}
		s := strings.Split(branch, "/")
		release := strings.TrimSuffix(s[1], "-stable")

		if err = git.Checkout(repoDir, branch); err != nil {
			return xerrors.Errorf("failed to git checkout: %w", err)
		}

		advisories, err := walkApkBuild(repoDir, release)
		if err != nil {
			return xerrors.Errorf("failed to walk APKBUILD: %w", err)
		}

		log.Printf("Saving secfixes: %s\n", release)
		for _, advisory := range advisories {
			filePath, err := constructFilePath(advisory.Release, advisory.Repository, advisory.Package, advisory.VulnerabilityID)
			if err != nil {
				return xerrors.Errorf("failed to construct file path: %w", err)
			}

			ok, err := utils.Exists(filePath)
			if err != nil {
				return xerrors.Errorf("error in file existence check: %w", err)
			} else if ok && !shouldOverwrite(filePath, advisory.FixedVersion) {
				continue
			}

			if err = utils.Write(filePath, advisory); err != nil {
				return xerrors.Errorf("failed to write Alpine secfixes: %w", err)
			}
		}
	}

	return nil
}

func retrieveIssue(issueURLs []string) error {
	var uncachedURLs []string
	var responses [][]byte
	for _, url := range issueURLs {
		issueID := strings.Split(path.Base(url), ".")[0]
		res := restoreCache(issueID)
		if res == nil {
			uncachedURLs = append(uncachedURLs, url)
			continue
		}
		responses = append(responses, res)
	}
	log.Printf("cached issues: %d\n", len(responses))
	log.Printf("uncached issues: %d\n", len(uncachedURLs))

	if len(uncachedURLs) > 0 {
		results, err := utils.FetchConcurrently(uncachedURLs, concurrency, wait, retry)
		if err != nil {
			return xerrors.Errorf("failed to fetch Alpine issue: %w", err)
		}
		responses = append(responses, results...)
	}

	log.Println("Parse issues")
	advisories, err := parseIssues(responses)
	if err != nil {
		return xerrors.Errorf("failed to parse Alpine issues: %w", err)
	}

	log.Println("Saving Alpine Security Issues...")
	bar := pb.StartNew(len(advisories))
	for _, advisory := range advisories {
		filePath, err := constructFilePath(advisory.Release, advisory.Repository, advisory.Package, advisory.VulnerabilityID)
		if err != nil {
			return xerrors.Errorf("failed to construct file path: %w", err)
		}

		if err = utils.Write(filePath, advisory); err != nil {
			log.Println(advisory.VulnerabilityID)
			return xerrors.Errorf("failed to write Alpine CVE details: %w", err)
		}
		bar.Increment()
	}
	bar.Finish()
	return nil
}

func saveCache(issueID int, content []byte) {
	dir := filepath.Join(utils.CacheDir(), "alpine-issues")
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Println(err)
		return
	}
	filePath := filepath.Join(dir, fmt.Sprintf("%d.json", issueID))
	if err := ioutil.WriteFile(filePath, content, 0700); err != nil {
		log.Println(err)
	}
	return
}

func restoreCache(issueID string) []byte {
	filePath := filepath.Join(utils.CacheDir(), "alpine-issues", fmt.Sprintf("%s.json", issueID))
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil
	}
	return content
}

func shouldOverwrite(filePath string, currentVersion string) bool {
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()

	var advisory Advisory
	if err = json.NewDecoder(f).Decode(&advisory); err != nil {
		return true
	}
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

func walkApkBuild(repoDir, release string) ([]Advisory, error) {
	var advisories []Advisory
	err := filepath.Walk(repoDir, func(path string, info os.FileInfo, err error) error {
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

		secFixes, err := parseSecFixes(string(content))
		if err != nil {
			return err
		} else if secFixes == nil {
			return nil
		}

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
		return nil
	})

	if err != nil {
		return nil, xerrors.Errorf("failed to walk Alpine aport: %w", err)
	}
	return advisories, nil
}

func constructFilePath(release, repository, pkg, cveID string) (string, error) {
	dir := filepath.Join(utils.VulnListDir(), alpineDir, release, repository, pkg)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return "", xerrors.Errorf("failed to create directory: %w", err)
	}

	return filepath.Join(dir, fmt.Sprintf("%s.json", cveID)), nil
}

func constructListURL(statusID, page int, createdOn time.Time) string {
	url, _ := url.Parse(trackerEndpoint)
	url.Path = path.Join(url.Path, trackerListPath)

	// "category_id=21&status_id=5&limit=100&page=1&created_on=>2019-05-02"
	q := url.Query()
	q.Set("category_id", "21")
	q.Set("status_id", fmt.Sprint(statusID))
	q.Set("limit", limit)
	q.Set("page", fmt.Sprint(page))
	q.Set("updated_on", fmt.Sprintf(">=%s", createdOn.Format("2006-01-02")))
	url.RawQuery = q.Encode()

	return url.String()
}

func constructDetailURL(issueID int) string {
	url, _ := url.Parse(trackerEndpoint)
	url.Path = path.Join(url.Path, "issues", fmt.Sprintf("%d.json", issueID))

	q := url.Query()
	q.Set("include", "changesets")
	url.RawQuery = q.Encode()

	return url.String()
}

func splitPath(filePath string) (string, string, string) {
	dir, base := filepath.Split(filePath)
	dir, pkg := filepath.Split(filepath.Clean(dir))
	repo := filepath.Base(filepath.Clean(dir))
	return filepath.Clean(repo), pkg, base
}

func parseIssues(responses [][]byte) ([]Advisory, error) {
	var advisories []Advisory
	bar := pb.StartNew(len(responses))
	for _, res := range responses {
		var detail IssueDetail
		if err := json.Unmarshal(res, &detail); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal Alpine issue JSON")
		}
		saveCache(detail.Issue.ID, res)

		advisoryList, err := parseIssue(&detail.Issue)
		if err != nil {
			return nil, err
		}
		advisories = append(advisories, advisoryList...)
		bar.Increment()
	}
	bar.Finish()
	return advisories, nil
}

func parseIssue(issue *Issue) ([]Advisory, error) {
	subject := strings.TrimSpace(issue.Subject)
	lastIndex := strings.LastIndex(subject, "(")
	if lastIndex < 0 {
		return nil, nil
	}
	cveStr := strings.Trim(subject[lastIndex:], "()")
	cves := strings.FieldsFunc(cveStr, func(r rune) bool {
		return r == ',' || r == '/'
	})
	var cveIDs []string
	for _, cve := range cves {
		cve = strings.TrimSpace(cve)
		if cveIDPattern.MatchString(cve) {
			cveIDs = append(cveIDs, cve)
		}
	}
	if len(cveIDs) == 0 {
		return nil, nil
	}

	// e.g. [3.3], [v3.9]
	index := strings.Index(subject, "]")
	if index < 0 {
		return nil, nil
	}
	release := strings.Trim(subject[:index], "[]v")

	if _, err := version.NewVersion(release); err != nil {
		return nil, nil
	}

	var advisories []Advisory
	for _, changeset := range issue.Changesets {
		updatedFiles, err := git.DiffPrev(repoDir, changeset.Revision)
		if err != nil {
			return nil, err
		}

		for _, file := range updatedFiles {
			// e.g. main/openssl/APKBUILD
			repo, pkg, filename := splitPath(file)
			if filename != "APKBUILD" || repo == "" || pkg == "" {
				continue
			}

			if !isSecurityFix(changeset.Revision, file, len(issue.Changesets)) {
				log.Println(changeset.Revision)
				continue
			}

			content, err := git.ShowFile(repoDir, changeset.Revision, file)
			if err != nil {
				return nil, err
			}

			pkgVer, pkgRel, err := parsePkgVerRel(content)
			if err != nil {
				return nil, err
			}

			version := pkgVer
			if pkgRel != "" {
				version += "-r" + pkgRel
			}
			for _, cveID := range cveIDs {
				advisory := Advisory{
					IssueID:         issue.ID,
					VulnerabilityID: cveID,
					Release:         release,
					Repository:      filepath.Clean(repo),
					Package:         filepath.Clean(pkg),
					FixedVersion:    version,
					Subject:         issue.Subject,
					Description:     issue.Description,
				}
				advisories = append(advisories, advisory)
			}
		}
	}
	return advisories, nil
}

func isSecurityFix(revision, file string, changesetCount int) bool {
	diffLines, err := git.DiffFile(repoDir, revision, file)
	if err != nil {
		return false
	}
	for _, line := range diffLines {
		if strings.HasPrefix(line, "+pkgver=") || strings.HasPrefix(line, "+pkgrel=") {
			return true
		} else if changesetCount == 1 && strings.HasPrefix(line, "+") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "+"))
			if strings.HasPrefix(line, "CVE-") && strings.HasSuffix(line, ".patch") {
				return true
			}
		}
	}
	return false
}

func parsePkgVerRel(content string) (pkgVer string, pkgRel string, err error) {
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

func parseSecFixes(content string) (secFixes map[string][]string, err error) {
	lines := strings.Split(content, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		//# secfixes:
		//#   2.4.11-r0:
		//#     - CVE-2018-19622
		//#   2.4.10-r0:
		//#     - CVE-2018-12086
		//#     - CVE-2018-18225
		if strings.HasPrefix(line, "# secfixes:") {
			// e.g. # secfixes:ss
			line = line[:strings.Index(line, ":")+1]
			secfixesStr := strings.TrimPrefix(line, "# ")
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
