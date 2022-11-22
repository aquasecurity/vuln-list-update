package oval

type Oval struct {
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
	Issued      Issued      `xml:"metadata>advisory>issued" json:",omitempty"`
}

type Reference struct {
	Source string `xml:"source,attr"`
	URI    string `xml:"ref_url,attr"`
	ID     string `xml:"ref_id,attr"`
}

type Cve struct {
	Impact string `xml:"impact,attr"`
	Href   string `xml:"href,attr"`
	ID     string `xml:",chardata"`
}

type Criteria struct {
	Operator   string      `xml:"operator,attr"`
	Criterias  []*Criteria `xml:"criteria"`
	Criterions []Criterion `xml:"criterion"`
}

type Criterion struct {
	Comment string `xml:"comment,attr"`
}

type Issued struct {
	Date string `xml:"date,attr" json:",omitempty"`
}
