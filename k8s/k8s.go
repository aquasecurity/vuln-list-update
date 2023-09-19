package k8s

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/aquasecurity/vuln-list-update/k8s/utils"
	"github.com/aquasecurity/vuln-list-update/osv"

	"github.com/hashicorp/go-multierror"
)

const (
	k8svulnDBURL = "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json"
	mitreURL     = "https://cveawg.mitre.org/api/cve"
	cveList      = "https://www.cve.org/"
)

type K8sVulnDB struct {
	Cves []*osv.OSV
}

type K8sCVE struct {
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

func Collect() (*K8sVulnDB, error) {
	response, err := http.Get(k8svulnDBURL)
	if err != nil {
		return nil, err
	}
	var db K8sCVE
	if err = json.NewDecoder(response.Body).Decode(&db); err != nil {
		return nil, err
	}
	return ParseVulnDBData(db)
}

const (
	// excludeNonCoreComponentsCves exclude  cves with missing data or non k8s core components
	excludeNonCoreComponentsCves = "CVE-2019-11255,CVE-2020-10749,CVE-2020-8554"
)

func ParseVulnDBData(db K8sCVE) (*K8sVulnDB, error) {
	fullVulnerabilities := make([]*osv.OSV, 0)
	for _, item := range db.Items {
		if strings.Contains(excludeNonCoreComponentsCves, item.ID) {
			continue
		}
		for _, cveID := range utils.GetMultiIDs(item.ID) {
			vulnerability, err := parseMitreCve(item.ExternalURL, cveID)
			if err != nil {
				return nil, err
			}
			if cveMissingImpoertantData(vulnerability) {
				continue
			}
			descComponent := utils.GetComponentFromDescription(item.ContentText, vulnerability.Package)
			fullVulnerabilities = append(fullVulnerabilities, &osv.OSV{
				ID:         cveID,
				Modified:   item.DatePublished,
				Published:  item.DatePublished,
				Summary:    item.Summary,
				Details:    vulnerability.Description,
				Affected:   getAffectedEvents(vulnerability.versions, getComponentName(descComponent, vulnerability.Package), vulnerability.CvssV3),
				References: []osv.Reference{{Url: mitreURL}, {Url: mitreURL}},
			})
		}
		err := validateCvesData(fullVulnerabilities)
		if err != nil {
			return nil, err
		}
	}
	return &K8sVulnDB{fullVulnerabilities}, nil
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
		}
		if len(av.LastAffected) > 0 && len(av.Fixed) == 0 {
			events = append(events, osv.Event{LastAffected: av.LastAffected})
		}
		if len(av.Introduced) > 0 && len(av.LastAffected) == 0 && len(av.Fixed) == 0 {
			events = append(events, osv.Event{LastAffected: av.Introduced})
		}
		ranges = append(ranges, osv.Range{
			Events: events,
		})
		affected = append(affected, osv.Affected{Ranges: ranges, Package: osv.Package{Name: p, Ecosystem: "k8s"}, Severities: []osv.Severity{{Type: cvss.Vector, Score: fmt.Sprintf("%.1f", cvss.Score)}}})
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
	return strings.ToLower(fmt.Sprintf("%s/%s", utils.UpstreamOrgByName(k8sComponent), utils.UpstreamRepoByName(k8sComponent)))
}

func validateCvesData(cves []*osv.OSV) error {
	var result error
	for _, cve := range cves {
		if len(cve.ID) == 0 {
			result = multierror.Append(result, fmt.Errorf("\nid is mssing on cve #%s", cve.ID))
		}
		if len(cve.Published) == 0 {
			result = multierror.Append(result, fmt.Errorf("\nCreatedAt is mssing on cve #%s", cve.ID))
		}
		if len(cve.Summary) == 0 {
			result = multierror.Append(result, fmt.Errorf("\nSummary is mssing on cve #%s", cve.ID))
		}
		for _, af := range cve.Affected {
			if len(strings.TrimPrefix(af.Package.Name, utils.UpstreamOrgByName(af.Package.Name))) == 0 {
				result = multierror.Append(result, fmt.Errorf("\nComponent is mssing on cve #%s", cve.ID))
			}
		}
		if len(cve.Details) == 0 {
			result = multierror.Append(result, fmt.Errorf("\nDescription is mssing on cve #%s", cve.ID))
		}
		if len(cve.Affected) == 0 {
			result = multierror.Append(result, fmt.Errorf("\nAffected Version is missing on cve #%s", cve.ID))
		}
		if len(cve.Affected) > 0 {
			for _, v := range cve.Affected {
				for _, s := range v.Severities {
					if len(s.Type) == 0 {
						result = multierror.Append(result, fmt.Errorf("\nVector is mssing on cve #%s", cve.ID))
					}
				}
				for _, r := range v.Ranges {
					for i := 1; i < len(r.Events); i++ {
						if len(r.Events[i-1].Introduced) == 0 {
							result = multierror.Append(result, fmt.Errorf("\nAffectedVersion Introduced is missing from cve #%s", cve.ID))
						}
						if len(r.Events[i].Fixed) == 0 && len(r.Events[i].LastAffected) == 0 {
							result = multierror.Append(result, fmt.Errorf("\nAffectedVersion Fixed and LastAffected are missing from cve #%s", cve.ID))
						}
					}
				}
			}
		}
		if len(cve.References) == 0 {
			result = multierror.Append(result, fmt.Errorf("\nUrls is mssing on cve #%s", cve.ID))
		}
	}
	return result
}

func cveMissingImpoertantData(vulnerability *Cve) bool {
	return len(vulnerability.versions) == 0 ||
		len(vulnerability.Package) == 0 ||
		len(vulnerability.CvssV3.Vector) == 0
}
