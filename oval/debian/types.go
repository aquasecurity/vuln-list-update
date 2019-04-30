package debian

import (
	"encoding/xml"
)

// Root : root object
type Root struct {
	XMLName     xml.Name    `xml:"oval_definitions" json:"-"`
	Generator   Generator   `xml:"generator"`
	Definitions Definitions `xml:"definitions"`
}

// Generator : >generator
type Generator struct {
	XMLName        xml.Name `xml:"generator" json:"-"`
	ProductName    string   `xml:"product_name"`
	ProductVersion string   `xml:"product_version"`
	SchemaVersion  string   `xml:"schema_version"`
	Timestamp      string   `xml:"timestamp"`
}

// Definitions : >definitions
type Definitions struct {
	XMLName     xml.Name     `xml:"definitions" json:"-"`
	Definitions []Definition `xml:"definition"`
}

// Definition : >definitions>definition
type Definition struct {
	XMLName  xml.Name `xml:"definition" json:"-"`
	ID       string   `xml:"id,attr"`
	Class    string   `xml:"class,attr"`
	Metadata Metadata `xml:"metadata"`
	Criteria Criteria `xml:"criteria"`
}

type Metadata struct {
	Title        string      `xml:"title"`
	AffectedList []Affected  `xml:"affected"`
	References   []Reference `xml:"reference"`
	Description  string      `xml:"description"`
	Debian       Debian      `xml:"debian"` // Debian

}

// Criteria : >definitions>definition>criteria
type Criteria struct {
	XMLName    xml.Name    `xml:"criteria" json:"-"`
	Operator   string      `xml:"operator,attr"`
	Criterias  []Criteria  `xml:"criteria"`
	Criterions []Criterion `xml:"criterion"`
}

// Criterion : >definitions>definition>criteria>*>criterion
type Criterion struct {
	XMLName xml.Name `xml:"criterion" json:"-"`
	Negate  bool     `xml:"negate,attr"`
	TestRef string   `xml:"test_ref,attr"`
	Comment string   `xml:"comment,attr"`
}

// Affected : >definitions>definition>metadata>affected
type Affected struct {
	XMLName  xml.Name `xml:"affected" json:"-"`
	Family   string   `xml:"family,attr"`
	Platform string   `xml:"platform"`
	Product  string   `xml:"product"`
}

// Reference : >definitions>definition>metadata>reference
type Reference struct {
	XMLName xml.Name `xml:"reference" json:"-"`
	Source  string   `xml:"source,attr"`
	RefID   string   `xml:"ref_id,attr"`
	RefURL  string   `xml:"ref_url,attr"`
}

// Debian : >definitions>definition>metadata>debian
type Debian struct {
	XMLName  xml.Name `xml:"debian" json:"-"`
	MoreInfo string   `xml:"moreinfo"`
	Date     string   `xml:"date" json:"-"`
}
