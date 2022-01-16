package ghsa

import githubql "github.com/shurcooL/githubv4"

type GetVulnerabilitiesQuery struct {
	SecurityVulnerabilities `graphql:"securityVulnerabilities(ecosystem: $ecosystem, first: $total, after: $cursor)"`
}

type SecurityVulnerabilities struct {
	Nodes    []GithubSecurityAdvisory
	PageInfo PageInfo
}
type PageInfo struct {
	EndCursor   githubql.String
	HasNextPage bool
}

type GithubSecurityAdvisory struct {
	Severity               string
	UpdatedAt              string
	Package                Package
	Advisory               Advisory
	FirstPatchedVersion    FirstPatchedVersion
	VulnerableVersionRange string
}

type GithubCVSS struct {
	Score        float32
	VectorString string
}

type GitHubClient struct {
	ApiKey string
}

type Package struct {
	Ecosystem string
	Name      string
}

type Advisory struct {
	DatabaseId  int
	Id          string
	GhsaId      string
	References  []Reference
	Identifiers []Identifier
	Description string
	Origin      string
	PublishedAt string
	Severity    string
	Summary     string
	UpdatedAt   string
	WithdrawnAt string
	CVSS        GithubCVSS
}

type Identifier struct {
	Type  string
	Value string
}

type Reference struct {
	Url string
}

type FirstPatchedVersion struct {
	Identifier string
}

type Version struct {
	FirstPatchedVersion    FirstPatchedVersion
	VulnerableVersionRange string
}

type GithubSecurityAdvisoryJson struct {
	Severity  string
	UpdatedAt string
	Package   Package
	Advisory  Advisory
	Versions  []Version
}
