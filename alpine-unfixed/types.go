package alpineunfixed

type unfixedVulnerability struct {
	ID       string     `json:"id,omitempty"`
	States   []state    `json:"state,omitempty"`
	CPEMatch []cpeMatch `json:"cpeMatch"`
}

type state struct {
	Fixed          bool   `json:"fixed"`
	Published      bool   `json:"published"`
	Repo           string `json:"repo"`
	PackageName    string `json:"packageName"`
	PackageVersion string `json:"packageVersion"`
}

type cpeMatch struct {
	MinVersion    string `json:"minimumVersion"`
	MinVersionOps string `json:"minimumVersionOp"`
	MaxVersion    string `json:"maximumVersion"`
	MaxVersionOps string `json:"maximumVersionOp"`
}
