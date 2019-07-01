package archlinux

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/knqyf263/vuln-list-update/utils"
	"golang.org/x/xerrors"
)

const (
	listURL      = "https://security.archlinux.org/issues/all.json"
	advisoryURL  = "https://security.archlinux.org/%s/generate/raw"
	baseURL      = "https://security.archlinux.org/%s.json"
	archlinuxDir = "archlinux"

	concurrency = 10
	wait        = 1
	retry       = 10
)

func Update() error {
	log.Println("Fetching Archlinux data...")
	issues, err := listAllArchlinuxIssues(0)
	if err != nil {
		return xerrors.Errorf("error in list Archlinux cves: %w", err)
	}

	urlsMap := make(map[string]struct{})
	for _, issue := range issues {
		for _, cveId := range issue.Issues {
			urlsMap[fmt.Sprintf(baseURL, cveId)] = struct{}{}
		}
	}
	var urls []string
	for url := range urlsMap {
		urls = append(urls, url)
	}

	cves := map[string]ArchlinuxCve{}
	cveJSONs, err := utils.FetchConcurrently(urls, concurrency, wait, retry)
	for _, cveJSON := range cveJSONs {
		var cve ArchlinuxCve
		if err = json.Unmarshal(cveJSON, &cve); err != nil {
			log.Printf("json decode error: %s", err)
			continue
		}
		cves[cve.Name] = cve
	}

	var avis []ArchlinuxVulnInfo
	for _, issue := range issues {
		for _, pkg := range issue.Packages {
			for _, cveId := range issue.Issues {
				avi := ArchlinuxVulnInfo{
					Package:     pkg,
					Status:      issue.Status,
					Affected:    issue.Affected,
					Fixed:       issue.Fixed,
					Ticket:      issue.Ticket,
					Name:        cves[cveId].Name,
					Groups:      cves[cveId].Groups,
					Type:        cves[cveId].Type,
					Severity:    cves[cveId].Severity,
					Vector:      cves[cveId].Vector,
					Description: cves[cveId].Description,
					Advisories:  cves[cveId].Advisories,
					References:  cves[cveId].References,
					Notes:       cves[cveId].Notes,
				}
				avis = append(avis, avi)
			}
		}
	}

	for _, avi := range avis {
		dir := filepath.Join(utils.VulnListDir(), archlinuxDir, avi.Package)
		os.MkdirAll(dir, os.ModePerm)
		filePath := filepath.Join(dir, fmt.Sprintf("%s.json", avi.Name))
		if err = utils.Write(filePath, avi); err != nil {
			return xerrors.Errorf("failed to write Archlinux CVE details: %w", err)
		}
	}
	return nil
}

func listAllArchlinuxIssues(wait int) (issues []ArchlinuxIssue, err error) {
	body, err := utils.FetchURL(listURL, "", retry)
	if err != nil {
		return issues, xerrors.Errorf("failed to fetch ArchLinux issues list: url: %s, err: %w", listURL, err)
	}
	var issueList []ArchlinuxIssue
	if err = json.Unmarshal(body, &issueList); err != nil {
		return nil, err
	}
	issues = append(issues, issueList...)
	time.Sleep(time.Duration(wait) * time.Second)

	return issues, nil
}
