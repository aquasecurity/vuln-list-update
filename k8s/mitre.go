package k8s

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	version "github.com/aquasecurity/go-version/pkg/version"
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
	Type   string
}

type Version struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	FixedIndex   int    `json:"-"`
}

func parseMitreCve(externalURL, mitreURL, cveID string) (*Cve, error) {
	if !strings.HasPrefix(externalURL, cveList) {
		// if no external url provided, return empty vulnerability to be skipped
		return &Cve{}, nil
	}
	response, err := http.Get(fmt.Sprintf("%s/%s", mitreURL, cveID))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
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
			case len(v.LessThan) > 0:
				if strings.HasSuffix(v.LessThan, ".0") {
					v.Version = "0"
				}
				introduce, fixed = updateVersions(v.LessThan, v.Version)
			case len(v.LessThanOrEqual) > 0:
				introduce, lastAffected = updateVersions(v.LessThanOrEqual, v.Version)
			case minorVersion(v.Version):
				requireMerge = true
				introduce = v.Version
			default:
				introduce, lastAffected = extractRangeVersions(v.Version)
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
	vector, vectorType := getMetrics(cve)
	description := getDescription(cve.Containers.Cna.Descriptions)
	return &Cve{
		Description: description,
		CvssV3: Cvssv3{
			Vector: vector,
			Type:   vectorType,
		},
		Package:  getComponentFromDescription(description, component),
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
	// example https://cveawg.mitre.org/api/cve/CVE-2023-2727
	if len(v.LessThanOrEqual) > 0 && v.LessThanOrEqual == "<=" {
		v.LessThanOrEqual = v.Version
	} else if len(v.LessThan) > 0 {
		switch {
		// example https://cveawg.mitre.org/api/cve/CVE-2019-11244
		case strings.HasSuffix(strings.TrimSpace(v.LessThan), "*"):
			v.Version = strings.TrimSpace(strings.ReplaceAll(v.LessThan, "*", ""))
			v.LessThan = ""
		}
	} else if len(v.Version) > 0 {
		switch {
		// example https://cveawg.mitre.org/api/cve/CVE-2020-8566
		case strings.HasPrefix(v.Version, "< "):
			v.LessThan = strings.TrimPrefix(v.Version, "< ")
			// example https://cveawg.mitre.org/api/cve/CVE-2020-8565
		case strings.HasPrefix(v.Version, "<= "):
			v.LessThanOrEqual = strings.TrimPrefix(v.Version, "<= ")
			//example https://cveawg.mitre.org/api/cve/CVE-2019-11247
		case strings.HasPrefix(strings.TrimSpace(v.Version), "prior to"):
			priorToVersion := strings.TrimSpace(strings.TrimPrefix(v.Version, "prior to"))
			if minorVersion(priorToVersion) {
				priorToVersion = priorToVersion + ".0"
				v.Version = priorToVersion
			}
			v.LessThan = priorToVersion
			// all version is vulnerable : https://cveawg.mitre.org/api/cve/CVE-2017-1002101
		case strings.HasSuffix(strings.TrimSpace(v.Version), ".x"):
			v.Version = strings.TrimSpace(strings.ReplaceAll(v.Version, ".x", ""))
		}
	}
	return &MitreVersion{
		Version:         trimString(v.Version, []string{"v", "V"}),
		LessThanOrEqual: trimString(v.LessThanOrEqual, []string{"v", "V"}),
		LessThan:        trimString(v.LessThan, []string{"v", "V"}),
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
	v1, err := version.Parse(s[i].Introduced)
	if err != nil {
		return false
	}
	v2, err := version.Parse(s[j].Introduced)
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
	// example: https://cveawg.mitre.org/api/cve/CVE-2019-11249
	sort.Sort(byVersion(affectedVersions))
	newAffectedVesion := make([]*Version, 0)
	minorVersions := make([]*Version, 0)
	for _, av := range affectedVersions {
		if minorVersion(av.Introduced) {
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
		currentVersion := fmt.Sprintf("%s.0", minorVersions[len(minorVersions)-1].Introduced)
		versionParts, err := versionParts(currentVersion)
		if err != nil {
			return nil, err
		}
		fixed := fmt.Sprintf("%d.%d.%d", versionParts[0], versionParts[1]+1, versionParts[2])
		newAffectedVesion = append(newAffectedVesion, &Version{Introduced: fmt.Sprintf("%s.0", minorVersions[0].Introduced), Fixed: fixed})
	}
	return newAffectedVesion, nil
}

func getMetrics(cve MitreCVE) (string, string) {
	var vectorString string
	for _, metric := range cve.Containers.Cna.Metrics {
		vectorString = metric.CvssV3_0.VectorString
		if len(vectorString) == 0 {
			vectorString = metric.CvssV3_1.VectorString
		}
	}
	return vectorString, "CVSS_V3"
}

func versionParts(version string) ([]int, error) {
	parts := strings.Split(version, ".")
	intParts := make([]int, 0)
	for _, p := range parts {
		i, err := strconv.Atoi(p)
		if err != nil {
			return nil, err
		}
		intParts = append(intParts, i)
	}
	return intParts, nil
}
