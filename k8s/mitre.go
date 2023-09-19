package k8s

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/aquasecurity/vuln-list-update/k8s/utils"
	"github.com/hashicorp/go-version"
)

type MitreCVE struct {
	CveMetadata CveMetadata
	Containers  Containers
}

type Containers struct {
	Cna struct {
		Affected []struct {
			Product  string
			Vendor   string
			Versions []*MitreVersion
		}
		Descriptions []Descriptions
		Metrics      []struct {
			CvssV3_1 struct {
				VectorString string
			}
			CvssV3_0 struct {
				VectorString string
			}
		}
	}
}

type MitreVersion struct {
	Status          string
	Version         string
	LessThanOrEqual string
	LessThan        string
	VersionType     string
}

type CveMetadata struct {
	CveId string
}

type Descriptions struct {
	Lang  string
	Value string
}

type Cve struct {
	Description string
	versions    []*Version
	CvssV3      Cvssv3
	Package     string
}

type Cvssv3 struct {
	Vector string
	Score  float64
}

type Version struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	FixedIndex   int    `json:"-"`
}

func parseMitreCve(externalURL string, cveID string) (*Cve, error) {
	if !strings.HasPrefix(externalURL, cveList) {
		// if no external url provided, return empty vulnerability to be skipped
		return &Cve{}, nil
	}
	response, err := http.Get(fmt.Sprintf("%s/%s", mitreURL, cveID))
	if err != nil {
		return nil, err
	}
	var cve MitreCVE
	if err = json.NewDecoder(response.Body).Decode(&cve); err != nil {
		return nil, err
	}
	vulnerableVersions := make([]*Version, 0)
	var component string
	var requireMerge bool
	for _, a := range cve.Containers.Cna.Affected {
		if len(component) == 0 {
			component = strings.ToLower(a.Product)
		}
		for _, sv := range a.Versions {
			if sv.Status != "affected" {
				continue
			}
			var introduce, lastAffected, fixed string
			v, ok := sanitizedVersions(sv)
			if !ok {
				continue
			}
			switch {
			case len(strings.TrimSpace(v.LessThanOrEqual)) > 0:
				introduce, lastAffected = utils.UpdateVersions(v.LessThanOrEqual, v.Version)
			case len(strings.TrimSpace(v.LessThan)) > 0:
				if strings.HasSuffix(v.LessThan, ".0") {
					v.Version = "0"
				}
				introduce, fixed = utils.UpdateVersions(v.LessThan, v.Version)
			case utils.MinorVersion(v.Version):
				requireMerge = true
				introduce = v.Version
			default:
				introduce, lastAffected = utils.ExtractRangeVersions(v.Version)
			}
			vulnerableVersions = append(vulnerableVersions, &Version{
				Introduced:   introduce,
				Fixed:        fixed,
				LastAffected: lastAffected,
			})
		}
	}
	if requireMerge {
		vulnerableVersions, err = mergeVersionRange(vulnerableVersions)
		if err != nil {
			return nil, err
		}
	}
	vector, score := getMetrics(cve)
	description := getDescription(cve.Containers.Cna.Descriptions)
	return &Cve{
		Description: description,
		CvssV3: Cvssv3{
			Vector: vector,
			Score:  score,
		},
		Package:  utils.GetComponentFromDescription(description, component),
		versions: vulnerableVersions,
	}, nil
}

func sanitizedVersions(v *MitreVersion) (*MitreVersion, bool) {
	if strings.Contains(v.Version, "n/a") && len(v.LessThan) == 0 && len(v.LessThanOrEqual) == 0 {
		return v, false
	}
	if (v.LessThanOrEqual == "unspecified" || v.LessThan == "unspecified") && len(v.Version) > 0 {
		return v, false
	}
	if len(v.LessThanOrEqual) > 0 {
		switch {
		case v.LessThanOrEqual == "<=":
			v.LessThanOrEqual = v.Version
		case strings.Contains(v.LessThanOrEqual, "<="):
			v.LessThanOrEqual = strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(v.LessThanOrEqual), "<=", ""))
		}
	} else if len(v.LessThan) > 0 {
		switch {
		case strings.HasPrefix(strings.TrimSpace(v.LessThan), "prior to"):
			v.LessThan = strings.TrimSpace(strings.TrimPrefix(v.Version, "prior to"))
		case strings.HasSuffix(strings.TrimSpace(v.LessThan), "*"):
			v.Version = strings.TrimSpace(strings.ReplaceAll(v.LessThan, "*", ""))
			v.LessThan = ""
		}
	} else if len(v.Version) > 0 {
		switch {
		case strings.HasPrefix(v.Version, "< "):
			v.LessThan = strings.TrimPrefix(v.Version, "< ")
		case strings.HasPrefix(v.Version, "<= "):
			v.LessThanOrEqual = strings.TrimPrefix(v.Version, "<= ")
		case strings.HasPrefix(strings.TrimSpace(v.Version), "prior to"):
			priorToVersion := strings.TrimSpace(strings.TrimPrefix(v.Version, "prior to"))
			if utils.MinorVersion(priorToVersion) {
				priorToVersion = priorToVersion + ".0"
				v.Version = priorToVersion
			}
			v.LessThan = priorToVersion
		case strings.HasSuffix(strings.TrimSpace(v.Version), ".x"):
			v.Version = strings.TrimSpace(strings.ReplaceAll(v.Version, ".x", ""))
		}
	}
	return &MitreVersion{
		Version:         utils.TrimString(v.Version, []string{"v", "V"}),
		LessThanOrEqual: utils.TrimString(v.LessThanOrEqual, []string{"v", "V"}),
		LessThan:        utils.TrimString(v.LessThan, []string{"v", "V"}),
	}, true
}

func getDescription(descriptions []Descriptions) string {
	for _, d := range descriptions {
		if d.Lang == "en" {
			return d.Value
		}
	}
	return ""
}

type byVersion []*Version

func (s byVersion) Len() int {
	return len(s)
}

func (s byVersion) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s byVersion) Less(i, j int) bool {
	v1, err := version.NewVersion(s[i].Introduced)
	if err != nil {
		return false
	}
	v2, err := version.NewVersion(s[j].Introduced)
	if err != nil {
		return false
	}
	return v1.LessThan(v2)
}

func mergeVersionRange(affectedVersions []*Version) ([]*Version, error) {
	// this special handling is made to handle to case of conceutive vulnable minor versions.
	// example: vulnerable 1.3, 1.4, 1.5, 1.6 and prior to versions 1.7.14, 1.8.9 will be form as follow:
	// Introduced: 1.3.0  Fixed: 1.7.14
	// Introduced: 1.8.0  Fixed: 1.8.9
	sort.Sort(byVersion(affectedVersions))
	newAffectedVesion := make([]*Version, 0)
	minorVersions := make([]*Version, 0)
	for _, av := range affectedVersions {
		if utils.MinorVersion(av.Introduced) {
			minorVersions = append(minorVersions, av)
		} else if strings.Count(av.Introduced, ".") > 1 && len(minorVersions) > 0 {
			newAffectedVesion = append(newAffectedVesion, &Version{
				Introduced:   fmt.Sprintf("%s.0", minorVersions[0].Introduced),
				LastAffected: av.LastAffected,
				Fixed:        av.Fixed,
			})
			minorVersions = minorVersions[:0]
			continue
		}
		if len(minorVersions) == 0 {
			newAffectedVesion = append(newAffectedVesion, av)
		}
	}

	// this special handling is made to handle to case of consecutive vulnable minor versions, wheen there is no fixed version is provided.
	// example: vulnerable 1.3, 1.4, 1.5, 1.6  will be form as follow:
	// Introduced: 1.3.0  Fixed: 1.7.0
	if len(minorVersions) > 0 {
		ver, err := version.NewSemver(fmt.Sprintf("%s.0", minorVersions[len(minorVersions)-1].Introduced))
		if err != nil {
			return nil, err
		}
		versionParts := ver.Segments()
		if len(versionParts) == 3 {
			fixed := fmt.Sprintf("%d.%d.%d", versionParts[0], versionParts[1]+1, versionParts[2])
			newAffectedVesion = append(newAffectedVesion, &Version{Introduced: fmt.Sprintf("%s.0", minorVersions[0].Introduced), Fixed: fixed})
		}
	}
	return newAffectedVesion, nil
}

func getMetrics(cve MitreCVE) (string, float64) {
	var vectorString string
	var score float64
	for _, metric := range cve.Containers.Cna.Metrics {
		vectorString = metric.CvssV3_0.VectorString
		if len(vectorString) == 0 {
			vectorString = metric.CvssV3_1.VectorString
		}
		_, score = utils.CvssVectorToScore(vectorString)
	}
	return vectorString, score
}
