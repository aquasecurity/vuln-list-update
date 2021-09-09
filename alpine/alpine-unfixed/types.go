package alpineunfix

type AlpineUnfix struct {
	ID       string     `json:"id,omitempty"`
	State    []State    `json:"state"`
	CPEMatch []CPEMatch `json:"cpeMatch"`
}

type State struct {
	Fixed          bool   `json:"fixed"`
	Repo           string `json:"repo,omitempty"`
	PackageName    string `json:"packageName,omitempty"`
	PackageVersion string `json:"packageVersion,omitempty"`
}

type CPEMatch struct {
	MinVersion    string `json:"minimumVersion"`
	MinVersionOps string `json:"minimumVersionOp"`
	MaxVersion    string `json:"maximumVersion"`
	MaxVersionOps string `json:"maximumVersionOp"`
}
