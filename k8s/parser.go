package k8s

import (
	"fmt"
	"strings"

	version "github.com/aquasecurity/go-version/pkg/version"
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

func trimString(s string, trimValues []string) string {
	for _, v := range trimValues {
		s = strings.Trim(s, v)
	}
	return strings.TrimSpace(s)
}

func updateVersions(to, introduce string) (string, string) {
	// Example: https://cveawg.mitre.org/api/cve/CVE-2023-2878
	if introduce == "0" {
		return introduce, to
	}
	// Example: https://cveawg.mitre.org/api/cve/CVE-2019-11243
	if minorVersion(introduce) {
		return introduce + ".0", to
	}
	// Example: https://cveawg.mitre.org/api/cve/CVE-2019-1002100
	if lIndex := strings.LastIndex(to, "."); lIndex != -1 {
		return strings.TrimSpace(fmt.Sprintf("%s.%s", to[:lIndex], "0")), to
	}
	return introduce, to
}

func extractRangeVersions(introduce string) (string, string) {
	// Example https://cveawg.mitre.org/api/cve/CVE-2021-25749
	var lastAffected string
	validVersion := make([]string, 0)
	// clean unwanted strings from versions
	versionRangeParts := strings.Split(introduce, " ")
	for _, p := range versionRangeParts {
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

func getMultiIDs(id string) []string {
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

func upstreamOrgByName(component string) string {
	for key, components := range UpstreamOrgName {
		for _, c := range strings.Split(components, ",") {
			if strings.TrimSpace(c) == strings.ToLower(component) {
				return key
			}
		}
	}
	return ""
}

func upstreamRepoByName(component string) string {
	if val, ok := UpstreamRepoName[component]; ok {
		return val
	}
	return component
}

func getComponentFromDescription(descriptions string, currentComponent string) string {
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
func minorVersion(version string) bool {
	return strings.Count(version, ".") == 1
}
