package k8s

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/osv"
	"github.com/aquasecurity/vuln-list-update/utils"
	uu "github.com/aquasecurity/vuln-list-update/utils"
)

const (
	k8svulnDBURL        = "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json"
	vulnListRepoTarBall = "https://api.github.com/repos/aquasecurity/vuln-list-k8s/tarball"
	mitreURL            = "https://cveawg.mitre.org/api/cve"
	cveList             = "https://www.cve.org/"
)

type VulnDB struct {
	Cves []*osv.OSV
}

type CVE struct {
	Items []Item `json:"items,omitempty"`
}

type Item struct {
	ID            string `json:"id,omitempty"`
	Summary       string `json:"summary,omitempty"`
	ContentText   string `json:"content_text,omitempty"`
	DatePublished string `json:"date_published,omitempty"`
	ExternalURL   string `json:"external_url,omitempty"`
	URL           string `json:"url,omitempty"`
}

func Collect() (*VulnDB, error) {
	response, err := http.Get(k8svulnDBURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var db CVE
	if err = json.NewDecoder(response.Body).Decode(&db); err != nil {
		return nil, err
	}
	cvesMap, err := getExitingCvesToModifiedMap()
	if err != nil {
		return nil, err
	}
	return ParseVulnDBData(db, cvesMap)
}

const (
	// excludeNonCoreComponentsCves exclude  cves with missing data or non k8s core components
	excludeNonCoreComponentsCves = "CVE-2019-11255,CVE-2020-10749,CVE-2020-8554"
)

func Update() error {
	if err := update(); err != nil {
		return xerrors.Errorf("error in k8s update: %w", err)
	}
	return nil
}

func update() error {
	log.Printf("Fetching k8s cves")

	k8sdb, err := Collect()
	if err != nil {
		return err
	}
	for _, cve := range k8sdb.Cves {
		if err = uu.Write(filepath.Join(uu.VulnListDir(), "upstream", fmt.Sprintf("%s.json", cve.ID)), cve); err != nil {
			return xerrors.Errorf("failed to save k8s CVE detail: %w", err)
		}
	}

	return nil
}

func ParseVulnDBData(db CVE, cvesMap map[string]string) (*VulnDB, error) {
	var fullVulnerabilities []*osv.OSV
	for _, item := range db.Items {
		for _, cveID := range getMultiIDs(item.ID) {
			// check if the current cve is older than the existing one on the vuln-list-k8s repo
			if strings.Contains(excludeNonCoreComponentsCves, item.ID) || olderCve(cveID, item.DatePublished, cvesMap) {
				continue
			}
			vulnerability, err := parseMitreCve(item.ExternalURL, cveID)
			if err != nil {
				return nil, err
			}
			if cveMissingImportantData(vulnerability) {
				continue
			}
			descComponent := getComponentFromDescription(item.ContentText, vulnerability.Package)
			fullVulnerabilities = append(fullVulnerabilities, &osv.OSV{
				ID:         cveID,
				Modified:   item.DatePublished,
				Published:  item.DatePublished,
				Summary:    item.Summary,
				Details:    vulnerability.Description,
				Affected:   getAffectedEvents(vulnerability.versions, getComponentName(descComponent, vulnerability.Package), vulnerability.CvssV3),
				References: []osv.Reference{{Url: item.URL}, {Url: item.ExternalURL}},
			})
		}
	}
	err := validateCvesData(fullVulnerabilities)
	if err != nil {
		return nil, err
	}
	return &VulnDB{fullVulnerabilities}, nil
}

func getAffectedEvents(v []*Version, p string, cvss Cvssv3) []osv.Affected {
	affected := make([]osv.Affected, 0)
	for _, av := range v {
		if len(av.Introduced) == 0 {
			continue
		}
		if av.Introduced == "0.0.0" {
			av.Introduced = "0"
		}
		events := make([]osv.Event, 0)
		ranges := make([]osv.Range, 0)
		if len(av.Introduced) > 0 {
			events = append(events, osv.Event{Introduced: av.Introduced})
		}
		if len(av.Fixed) > 0 {
			events = append(events, osv.Event{Fixed: av.Fixed})
		} else if len(av.LastAffected) > 0 {
			events = append(events, osv.Event{LastAffected: av.LastAffected})
		} else if len(av.Introduced) > 0 && len(av.LastAffected) == 0 && len(av.Fixed) == 0 {
			events = append(events, osv.Event{LastAffected: av.Introduced})
		}
		ranges = append(ranges, osv.Range{
			Events: events,
		})
		affected = append(affected, osv.Affected{Ranges: ranges, Package: osv.Package{Name: p, Ecosystem: "kubernetes"}, Severities: []osv.Severity{{Type: cvss.Type, Score: cvss.Vector}}})
	}
	return affected
}

func getComponentName(k8sComponent string, mitreComponent string) string {
	if len(k8sComponent) == 0 {
		k8sComponent = mitreComponent
	}
	if strings.ToLower(mitreComponent) != "kubernetes" {
		k8sComponent = mitreComponent
	}
	return strings.ToLower(fmt.Sprintf("%s/%s", upstreamOrgByName(k8sComponent), upstreamRepoByName(k8sComponent)))
}

func validateCvesData(cves []*osv.OSV) error {
	var result error
	for _, cve := range cves {
		if len(cve.ID) == 0 {
			result = errors.Join(result, fmt.Errorf("\nid is mssing on cve #%s", cve.ID))
		}
		if len(cve.Published) == 0 {
			result = errors.Join(result, fmt.Errorf("\nCreatedAt is mssing on cve #%s", cve.ID))
		}
		if len(cve.Summary) == 0 {
			result = errors.Join(result, fmt.Errorf("\nSummary is mssing on cve #%s", cve.ID))
		}
		for _, af := range cve.Affected {
			if len(strings.TrimPrefix(af.Package.Name, upstreamOrgByName(af.Package.Name))) == 0 {
				result = errors.Join(result, fmt.Errorf("\nComponent is mssing on cve #%s", cve.ID))
			}
		}
		if len(cve.Details) == 0 {
			result = errors.Join(result, fmt.Errorf("\nDescription is mssing on cve #%s", cve.ID))
		}
		if len(cve.Affected) == 0 {
			result = errors.Join(result, fmt.Errorf("\nAffected Version is missing on cve #%s", cve.ID))
		}
		if len(cve.Affected) > 0 {
			for _, v := range cve.Affected {
				for _, s := range v.Severities {
					if len(s.Type) == 0 {
						result = errors.Join(result, fmt.Errorf("\nVector is mssing on cve #%s", cve.ID))
					}
				}
				for _, r := range v.Ranges {
					for i := 1; i < len(r.Events); i++ {
						if len(r.Events[i-1].Introduced) == 0 {
							result = errors.Join(result, fmt.Errorf("\nAffectedVersion Introduced is missing from cve #%s", cve.ID))
						}
						if len(r.Events[i].Fixed) == 0 && len(r.Events[i].LastAffected) == 0 {
							result = errors.Join(result, fmt.Errorf("\nAffectedVersion Fixed and LastAffected are missing from cve #%s", cve.ID))
						}
					}
				}
			}
		}
		if len(cve.References) == 0 {
			result = errors.Join(result, fmt.Errorf("\nUrls is mssing on cve #%s", cve.ID))
		}
	}
	return result
}

func cveMissingImportantData(vulnerability *Cve) bool {
	return len(vulnerability.versions) == 0 ||
		len(vulnerability.Package) == 0 ||
		len(vulnerability.CvssV3.Vector) == 0
}

// getExitingCvesToModifiedMap get the existing cves from vuln-list-k8s repo and map it to cve id and last updated
func getExitingCvesToModifiedMap() (map[string]string, error) {
	response, err := http.Get(vulnListRepoTarBall)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	return cveIDToModifiedMap(utils.VulnListDir())
}

// cveIDToModifiedMap read existing cves from vulnList folder and map it to cve id and last updated
func cveIDToModifiedMap(cveFolderPath string) (map[string]string, error) {
	mapCveTime := make(map[string]string)
	if _, err := os.Stat(cveFolderPath); os.IsNotExist(err) {
		return mapCveTime, nil
	}
	fileInfo, err := os.ReadDir(cveFolderPath)
	if err != nil {
		return mapCveTime, err
	}
	for _, file := range fileInfo {
		if file.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(cveFolderPath, file.Name()))
		if err != nil {
			return nil, err
		}
		var cve osv.OSV
		err = json.Unmarshal([]byte(strings.ReplaceAll(string(b), "\n", "")), &cve)
		if err != nil {
			return nil, err
		}
		mapCveTime[cve.ID] = cve.Modified
	}
	return mapCveTime, nil
}

// olderCve check if the current cve is older than the existing one
func olderCve(cveID string, currentCVEUpdated string, existCveLastUpdated map[string]string) bool {
	if len(existCveLastUpdated) == 0 {
		return false
	}
	var lastUpdated string
	var ok bool
	if lastUpdated, ok = existCveLastUpdated[cveID]; !ok {
		return false
	}
	existLastUpdated, err := time.Parse(time.RFC3339, lastUpdated)
	if err != nil {
		return false
	}
	currentLastUpdated, err := time.Parse(time.RFC3339, currentCVEUpdated)
	if err != nil {
		return false
	}
	// check if the current collcted cve is older or same as the existing one
	if currentLastUpdated.Before(existLastUpdated) || currentLastUpdated == existLastUpdated {
		return true
	}

	return false
}
