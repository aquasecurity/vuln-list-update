package anolis

type Oval struct {
	Definitions []Definition `xml:"definitions>definition"`
}

type Definition struct {
	ID       string   `xml:"id,attr"`
	Version  string   `xml:"version,attr"`
	Class    string   `xml:"class,attr"`
	Metadata Metadata `xml:"metadata"`
	Criteria Criteria `xml:"criteria"`
}

type Metadata struct {
	Title       string      `xml:"title"`
	Affected    Affected    `xml:"affected"`
	References  []Reference `xml:"reference"`
	Description string      `xml:"description"`
	Advisory    Advisory    `xml:"advisory"`
}

type Affected struct {
	Family   string   `xml:"family,attr"`
	Platform []string `xml:"platform"`
}

type Reference struct {
	RefID  string `xml:"ref_id,attr"`
	RefURL string `xml:"ref_url,attr"`
	Source string `xml:"source,attr"`
}

type Advisory struct {
	Severity        string   `xml:"severity"`
	Issued          Issued   `xml:"issued"`
	Updated         Issued   `xml:"updated"`
	Cves            []Cve    `xml:"cve"`
	AffectedCpeList []string `xml:"affected_cpe_list>cpe"`
}

type Cve struct {
	ID     string `xml:",chardata"`
	CVSS3  string `xml:"cvss3,attr"`
	Impact string `xml:"impact,attr"`
	Href   string `xml:"href,attr"`
	CWE    string `xml:"cwe,attr"`
	Public string `xml:"public,attr"`
}

type Issued struct {
	Date string `xml:"date,attr"`
}

type Criteria struct {
	Operator   string      `xml:"operator,attr"`
	Criterias  []*Criteria `xml:"criteria"`
	Criterions []Criterion `xml:"criterion"`
}

type Criterion struct {
	Comment string `xml:"comment,attr"`
	TestRef string `xml:"test_ref,attr"`
}
