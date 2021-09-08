package alpineunfix

type AlpineUnfix struct {
	ID       string     `json:"id,omitempty"`
	State    []State    `json:"state"`
	CPEMatch []CPEMatch `json:"cpeMatch"`
}

type State struct {
	Fixed          bool   `json:"fixed,omitempty"`
	Repo           string `json:"repo,omitempty"`
	PackageName    string `json:"packageName,omitempty"`
	PackageVersion string `json:"packageVersion,omitempty"`
}

type SaveJsonFormat struct {
	DistroVersion string              `json:"distroversion,omitempty"`
	RepoName      string              `json:"reponame,omitempty"`
	UnfixVersion  map[string][]string `json:"unfix,omitempty"`
	PkgName       string              `json:"name,omitempty"`
}

type CPEMatch struct {
	MinVersion    string `json:"minimumVersion"`
	MinVersionOps string `json:"minimumVersionOp"`
	MaxVersion    string `json:"maximumVersion"`
	MaxVersionOps string `json:"maximumVersionOp"`
}
