package oval

type OvalDefinitions struct {
	Definitions []Definition `xml:"definitions>definition"`
}

type Definition struct {
	Title       string      `xml:"metadata>title"`
	Description string      `xml:"metadata>description"`
	Platform    []string    `xml:"metadata>affected>platform"`
	References  []Reference `xml:"metadata>reference"`
	Criteria    Criteria    `xml:"criteria"`
	Severity    string      `xml:"metadata>advisory>severity"`
	Cves        []Cve       `xml:"metadata>advisory>cve"`
	Issued      Date        `xml:"metadata>advisory>issued"`
	Updated     Date        `xml:"metadata>advisory>updated"`
}

type Reference struct {
	Source string `xml:"source,attr"`
	URI    string `xml:"ref_url,attr"`
	ID     string `xml:"ref_id,attr"`
}

type Cve struct {
	ID string `xml:",chardata"`
}

type Criteria struct {
	Operator   string      `xml:"operator,attr"`
	Criterias  []*Criteria `xml:"criteria"`
	Criterions []Criterion `xml:"criterion"`
}

type Criterion struct {
	Comment string `xml:"comment,attr"`
}

type Date struct {
	Date string `xml:"date,attr"`
}
