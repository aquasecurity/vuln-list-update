package k8s

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/osv"
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
	var db CVE
	if err = json.NewDecoder(response.Body).Decode(&db); err != nil {
		return nil, err
	}
	defer response.Body.Close()
	return ParseVulnDBData(db)
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

func ParseVulnDBData(db CVE) (*VulnDB, error) {
	var fullVulnerabilities []*osv.OSV
	cvesMap, err := getCureentCvesMap()
	if err != nil {
		return nil, err
	}
	for _, item := range db.Items {
		if strings.Contains(excludeNonCoreComponentsCves, item.ID) {
			continue
		}
		for _, cveID := range getMultiIDs(item.ID) {
			if olderCve(cveID, item.DatePublished, cvesMap) {
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
		err := validateCvesData(fullVulnerabilities)
		if err != nil {
			return nil, err
		}
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
		affected = append(affected, osv.Affected{Ranges: ranges, Package: osv.Package{Name: p, Ecosystem: "kubernetes"}, Severities: []osv.Severity{{Type: cvss.Vector, Score: fmt.Sprintf("%.1f", cvss.Score)}}})
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

func getCureentCvesMap() (map[string]string, error) {
	response, err := http.Get(vulnListRepoTarBall)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	return tarToMap(response.Body)

}

// tarToMap read ewxisting cves from tar file and map it to cve id and last updated
func tarToMap(reader io.ReadCloser) (map[string]string, error) {
	cveTimeMap := make(map[string]string)
	gz, err := gzip.NewReader(reader)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = gz.Close()
	}()
	tarReader := tar.NewReader(gz)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		info := header.FileInfo()
		switch header.Typeflag {

		// if its a dir and it doesn't exist create it
		case tar.TypeDir:
			continue
		case tar.TypeReg:
			if strings.Contains(info.Name(), "CVE-") && strings.HasSuffix(info.Name(), ".json") {
				b, err := io.ReadAll(tarReader)
				if err != nil {
					return nil, err
				}
				var cve osv.OSV
				err = json.Unmarshal([]byte(strings.ReplaceAll(string(b), "\n", "")), &cve)
				if err != nil {
					return nil, err
				}
				cveTimeMap[cve.ID] = cve.Modified
			}
		}
	}
	return cveTimeMap, nil
}

// olderCve check if the current cve is older than the existing one
func olderCve(cveID string, currentCVEUpdated string, existCveLastUpdated map[string]string) bool {
	if len(existCveLastUpdated) == 0 {
		return false
	}
	if lastUpdated, ok := existCveLastUpdated[cveID]; ok {
		existastUpdated, err := time.Parse(time.RFC3339, lastUpdated)
		if err != nil {
			return false
		}
		currentLastUpdated, err := time.Parse(time.RFC3339, currentCVEUpdated)
		if err != nil {
			return false
		}
		// check if the current collcted cve is older or same as the existing one
		if currentLastUpdated.Before(existastUpdated) || currentLastUpdated == existastUpdated {
			return true
		}
	}
	return false
}
