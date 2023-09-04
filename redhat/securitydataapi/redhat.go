package securitydataapi

import (
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	listURL = "https://access.redhat.com/labs/securitydataapi/cve.json?page=%d&after=%s&per_page=500"
	cveURL  = "https://access.redhat.com/labs/securitydataapi/cve/%s.json"
	apiDir  = "api"

	concurrency = 10
	wait        = 1
	retry       = 20 // Red Hat Security Data API is unstable
)

func Update() error {
	now := time.Now()
	for year := 1996; year <= now.Year(); year++ {
		if err := update(year); err != nil {
			return xerrors.Errorf("error in RedHat update: %w", err)
		}
	}
	return nil
}

func update(year int) error {
	log.Printf("Fetching RedHat: year %d\n", year)
	after := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
	before := after.AddDate(1, 0, 0)
	entries, err := listAllRedhatCves(after.Format("2006-01-02"), before.Format("2006-01-02"), 0)
	if err != nil {
		return xerrors.Errorf("error in list RedHat cves: %w", err)
	}

	urls := make([]string, len(entries))
	for i, entry := range entries {
		url := fmt.Sprintf(cveURL, entry.CveID)
		urls[i] = url
	}

	cves, err := retrieveRedhatCveDetails(urls)
	if err != nil {
		return xerrors.Errorf("failed to retrieve RedHat CVE details: %w", err)
	}

	for cveID, cve := range cves {
		if err = utils.SaveCVEPerYear(filepath.Join(utils.VulnListDir(), apiDir), cveID, cve); err != nil {
			return xerrors.Errorf("failed to save RedHat CVE detail: %w", err)
		}
	}

	return nil
}

// listAllRedhatCves returns the list of all CVEs from RedHat API
// https://access.redhat.com/documentation/en-us/red_hat_security_data_api/0.1/html-single/red_hat_security_data_api/#list_all_cves
func listAllRedhatCves(after, before string, wait int) (entries []RedhatEntry, err error) {
	for page := 1; ; page++ {
		log.Printf("page %d\n", page)
		url := fmt.Sprintf(listURL, page, after)
		if before != "" {
			url += fmt.Sprintf("&before=%s", before)
		}
		body, err := utils.FetchURL(url, "", retry)
		if err != nil {
			return entries, xerrors.Errorf("failed to fetch RedHat CVEs list: url: %s, err: %w", url, err)
		}

		var entryList []RedhatEntry
		if err = json.Unmarshal(body, &entryList); err != nil {
			return nil, err
		}
		if len(entryList) == 0 {
			break
		}
		entries = append(entries, entryList...)
		time.Sleep(time.Duration(wait) * time.Second)
	}
	return entries, nil
}

// retrieveRedhatCveDetails returns full CVE details from RedHat API
// https://access.redhat.com/documentation/en-us/red_hat_security_data_api/0.1/html-single/red_hat_security_data_api/#retrieve_a_cve
func retrieveRedhatCveDetails(urls []string) (map[string]*RedhatCVEJSON, error) {
	cves := map[string]*RedhatCVEJSON{}

	cveJSONs, err := utils.FetchConcurrently(urls, concurrency, wait, retry)
	if err != nil {
		log.Printf("failed to fetch cve data from RedHat. err: %s", err)
	}

	for _, cveJSON := range cveJSONs {
		cve := &RedhatCVEJSON{}
		if err = json.Unmarshal(cveJSON, cve); err != nil {
			log.Printf("json decode error: %s", err)
			continue
		}
		cves[cve.Name] = cve
	}

	return cves, nil
}
