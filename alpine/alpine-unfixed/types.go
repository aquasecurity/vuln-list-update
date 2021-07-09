package alpineunfix

type State struct {
	PackageVersion string `json:"packageVersion,omitempty"`
	Vulnerability  string `json:"vuln,omitempty"`
	Fixed          bool   `json:"fixed,omitempty"`
}

type Item struct {
	State    []State    `json:"state,omitempty"`
	CPEMatch []CPEMatch `json:"cpeMatch,omitempty"`
}

type ReleaseInfo struct {
	Id    string `json:"id,omitempty"`
	Items []Item `json:"items,omitempty"`
}

type CPEMatch struct {
	Package       string `json:"package"`
	Vulnerability string `json:"vuln"`
}

type VulnVersionMap map[string][]string

type SaveJsonFormat struct {
	DistroVersion string              `json:"distroversion,omitempty"`
	RepoName      string              `json:"reponame,omitempty"`
	UnfixVersion  map[string][]string `json:"unfix,omitempty"`
	PkgName       string              `json:"name,omitempty"`
}
