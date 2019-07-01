package archlinux

type ArchlinuxIssue struct {
	Packages []string `json:"packages"`
	Issues   []string `json:"issues"`

	Status   string      `json:"status"`
	Affected string      `json:"affected"`
	Fixed    string      `json:"fixed"`
	Ticket   interface{} `json:"ticket"`
}

type ArchlinuxCve struct {
	Name        string      `json:"name"`
	Groups      []string    `json:"groups"`
	Type        string      `json:"type"`
	Severity    string      `json:"severity"`
	Vector      string      `json:"vector"`
	Description string      `json:"description"`
	Advisories  []string    `json:"advisories"`
	References  []string    `json:"references"`
	Notes       interface{} `json:"notes"`
}

type ArchlinuxVulnInfo struct {
	Package string `json:"package"`

	// ArchlinuxIssue
	Status   string      `json:"status"`
	Affected string      `json:"affected"`
	Fixed    string      `json:"fixed"`
	Ticket   interface{} `json:"ticket"`

	// ArchlinuxCve
	Name        string      `json:"name"`
	Groups      []string    `json:"groups"`
	Type        string      `json:"type"`
	Severity    string      `json:"severity"`
	Vector      string      `json:"vector"`
	Description string      `json:"description"`
	Advisories  []string    `json:"advisories"`
	References  []string    `json:"references"`
	Notes       interface{} `json:"notes"`
}
