package cvrf

import (
	"encoding/xml"
	"log"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

// cveCvrfDoc is a minimal parse of SUSE cvrf-cve/* XML for CVSS score extraction.
type cveCvrfDoc struct {
	XMLName xml.Name    `xml:"cvrfdoc"`
	Vuln    cveCvrfVuln `xml:"http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln Vulnerability"`
}

type cveCvrfVuln struct {
	CVSSScoreSets cveCvrfCVSSScoreSets `xml:"http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln CVSSScoreSets"`
}

type cveCvrfCVSSScoreSets struct {
	ScoreSetV2 []cveScoreSetV2 `xml:"http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln ScoreSetV2"`
	ScoreSetV3 []cveScoreSetV3 `xml:"http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln ScoreSetV3"`
}

type cveScoreSetV2 struct {
	BaseScoreV2 string `xml:"http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln BaseScoreV2"`
	VectorV2    string `xml:"http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln VectorV2"`
}

type cveScoreSetV3 struct {
	BaseScoreV3 string `xml:"http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln BaseScoreV3"`
	VectorV3    string `xml:"http://docs.oasis-open.org/csaf/ns/csaf-cvrf/v1.2/vuln VectorV3"`
}

func parseCVECvrfScoreSets(b []byte) ([]ScoreSet, error) {
	var doc cveCvrfDoc
	if err := xml.Unmarshal(b, &doc); err != nil {
		return nil, xerrors.Errorf("decode CVE CVRF: %w", err)
	}
	return scoreSetsFromCVE12(doc.Vuln.CVSSScoreSets), nil
}

func (c Config) mergeCVEDetailsFromCVEFeed(cv *Cvrf, cache map[string][]ScoreSet) {
	if c.CvrfCVEURL == "" {
		return
	}
	base := strings.TrimSuffix(c.CvrfCVEURL, "/")
	for i := range cv.Vulnerabilities {
		cveID := strings.TrimSpace(cv.Vulnerabilities[i].CVE)
		if cveID == "" {
			continue
		}
		if sets, ok := cache[cveID]; ok {
			if len(sets) > 0 {
				cv.Vulnerabilities[i].CVSSScoreSets = sets
			}
			continue
		}
		u := base + "/cvrf-" + cveID + ".xml"
		b, err := utils.FetchURL(u, "", c.Retry)
		if err != nil {
			log.Printf("CVE CVRF fetch skipped for %s: %v", cveID, err)
			cache[cveID] = nil
			continue
		}
		sets, err := parseCVECvrfScoreSets(b)
		if err != nil {
			log.Printf("CVE CVRF parse failed for %s: %v", cveID, err)
			cache[cveID] = nil
			continue
		}
		cache[cveID] = sets
		if len(sets) > 0 {
			cv.Vulnerabilities[i].CVSSScoreSets = sets
		}
	}
}

func scoreSetsFromCVE12(cvss cveCvrfCVSSScoreSets) []ScoreSet {
	var out []ScoreSet
	for _, s := range cvss.ScoreSetV2 {
		if strings.TrimSpace(s.BaseScoreV2) == "" && strings.TrimSpace(s.VectorV2) == "" {
			continue
		}
		out = append(out, ScoreSet{BaseScore: s.BaseScoreV2, Vector: s.VectorV2})
	}
	for _, s := range cvss.ScoreSetV3 {
		if strings.TrimSpace(s.BaseScoreV3) == "" && strings.TrimSpace(s.VectorV3) == "" {
			continue
		}
		out = append(out, ScoreSet{BaseScore: s.BaseScoreV3, Vector: s.VectorV3})
	}
	return out
}
