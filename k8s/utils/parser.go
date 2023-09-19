package utils

import (
	"fmt"

	"strings"

	version "github.com/aquasecurity/go-pep440-version"
	"github.com/goark/go-cvss/v3/metric"
	"golang.org/x/exp/maps"
)

const (
	LessThanOrEqual = "lessThenOrEqual"
	LessThen        = "lessThen"
)

var (
	UpstreamOrgName = map[string]string{
		"k8s.io":      "controller-manager,kubelet,apiserver,kubectl,kubernetes,kube-scheduler,kube-proxy",
		"sigs.k8s.io": "secrets-store-csi-driver",
	}

	UpstreamRepoName = map[string]string{
		"kube-controller-manager":  "controller-manager",
		"kubelet":                  "kubelet",
		"kube-apiserver":           "apiserver",
		"kubectl":                  "kubectl",
		"kubernetes":               "kubernetes",
		"kube-scheduler":           "kube-scheduler",
		"kube-proxy":               "kube-proxy",
		"api server":               "apiserver",
		"secrets-store-csi-driver": "secrets-store-csi-driver",
	}
)

func TrimString(version string, trimValues []string) string {
	for _, v := range trimValues {
		version = strings.ReplaceAll(version, v, "")
	}
	return strings.TrimSpace(version)
}

func CvssVectorToScore(vector string) (string, float64) {
	bm, err := metric.NewBase().Decode(vector) //CVE-2020-1472: ZeroLogon
	if err != nil {
		return "", 0.0
	}
	return bm.Severity().String(), bm.Score()
}

func UpdateVersions(to, introduce string) (string, string) {
	if introduce == "0" {
		return introduce, to
	}

	if MinorVersion(introduce) {
		return introduce + ".0", to
	}

	if lIndex := strings.LastIndex(to, "."); lIndex != -1 {
		return strings.TrimSpace(fmt.Sprintf("%s.%s", to[:lIndex], "0")), to
	}
	return introduce, to
}

func ExtractRangeVersions(introduce string) (string, string) {
	var lastAffected string
	validVersion := make([]string, 0)
	// clean unwanted strings from versions
	versionParts := strings.Split(TrimString(introduce, maps.Keys(UpstreamRepoName)), " ")
	for _, p := range versionParts {
		candidate, err := version.Parse(p)
		if err != nil {
			continue
		}
		validVersion = append(validVersion, candidate.String())
	}
	if len(validVersion) >= 1 {
		introduce = strings.TrimSpace(validVersion[0])
	}
	if len(validVersion) == 2 {
		lastAffected = strings.TrimSpace(validVersion[1])
	}
	return introduce, lastAffected
}

func GetMultiIDs(id string) []string {
	var idsList []string
	if strings.Contains(id, ",") {
		idParts := strings.Split(id, ",")
		for _, p := range idParts {
			if strings.HasPrefix(strings.TrimSpace(p), "CVE-") {
				idsList = append(idsList, strings.TrimSpace(p))
			}
		}
		return idsList
	}
	return []string{id}
}

func UpstreamOrgByName(component string) string {
	for key, components := range UpstreamOrgName {
		for _, c := range strings.Split(components, ",") {
			if strings.TrimSpace(c) == strings.ToLower(component) {
				return key
			}
		}
	}
	return ""
}

func UpstreamRepoByName(component string) string {
	if val, ok := UpstreamRepoName[component]; ok {
		return val
	}
	return component
}

func GetComponentFromDescription(descriptions string, currentComponent string) string {
	if strings.ToLower(currentComponent) != "kubernetes" {
		return currentComponent
	}
	var compName string
	var compCounter int
	var kubeCtlVersionFound bool
	CoreComponentsNaming := []string{"kube-controller-manager", "kubelet", "kube-apiserver", "kubectl", "kube-scheduler", "kube-proxy", "secrets-store-csi-driver", "api server"}

	for _, key := range CoreComponentsNaming {
		if strings.Contains(strings.ToLower(descriptions), key) {
			c := strings.Count(strings.ToLower(descriptions), key)
			if UpstreamRepoName[key] == compName {
				compCounter = compCounter + c
			}
			if strings.Contains(strings.ToLower(descriptions), "kubectl version") {
				kubeCtlVersionFound = true
			}
			if c > compCounter {
				compCounter = c
				compName = UpstreamRepoName[key]
			}
		}
	}
	// in case found kubectl in env description and only one component found or no component found then fallback to k8s.io/kubernetes component
	if len(compName) == 0 || (kubeCtlVersionFound && compName == "kubectl" && compCounter == 1) {
		return currentComponent
	}
	return compName
}

// MinorVersion returns true if version is minor version 1.1 or 2.2 and etc
func MinorVersion(version string) bool {
	return strings.Count(version, ".") == 1
}
