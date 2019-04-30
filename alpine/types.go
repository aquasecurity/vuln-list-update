package alpine

type IssueList struct {
	Issues []Issue
}

type IssueDetail struct {
	Issue Issue
}

type Issue struct {
	ID           int
	Subject      string
	Description  string
	CustomFields []CustomField
	Changesets   []Changeset
}

type CustomField struct {
	ID    int
	Name  string
	Value string
}

type Changeset struct {
	Revision string
	Comments string
}

type Advisory struct {
	IssueID         int
	VulnerabilityID string // e.g. CVE-2016-6258, XSA-182
	Release         string // e.g. 3.7
	Package         string // e.g. openssl
	Repository      string // main or community
	FixedVersion    string // e.g. 1.2.3-r4
	Subject         string
	Description     string
}

type SecFixes struct {
	SecFixes map[string][]string
}
