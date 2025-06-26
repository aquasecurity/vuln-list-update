package rootio

// CVEFeed represents the root structure of the CVE feed API response
type CVEFeed map[string][]DistroData

// DistroData represents vulnerability data for a specific distribution version
type DistroData struct {
	DistroVersion string        `json:"distroversion"`
	Packages      []PackageData `json:"packages"`
}

// PackageData represents a package with its vulnerability information
type PackageData struct {
	Pkg PackageInfo `json:"pkg"`
}

// PackageInfo contains the package name and CVE information
type PackageInfo struct {
	Name string             `json:"name"`
	CVEs map[string]CVEInfo `json:"cves"`
}

// CVEInfo contains vulnerability details for a specific CVE
type CVEInfo struct {
	VulnerableRanges []string `json:"vulnerable_ranges"`
	FixedVersions    []string `json:"fixed_versions"`
}
