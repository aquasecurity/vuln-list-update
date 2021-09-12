package alpineunfixed

type unfixedVulnerability struct {
	ID     string  `json:"id,omitempty"`
	States []state `json:"state,omitempty"`
}

type state struct {
	Fixed          bool   `json:"fixed"`
	Published      bool   `json:"published"`
	Repo           string `json:"repo"`
	PackageName    string `json:"packageName"`
	PackageVersion string `json:"packageVersion"`
}
