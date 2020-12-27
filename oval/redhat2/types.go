package redhat2

import (
	"encoding/xml"
)

type OvalDefinitions struct {
	XMLName     xml.Name    `xml:"oval_definitions"`
	Generator   Generator   `xml:"generator`
	Definitions Definitions `xml:"definitions"`

	Tests   Tests   `xml:"tests"`
	Objects Objects `xml:"objects"`
	States  States  `xml:"states"`
}

type Generator struct {
	ProductName    string `xml:"product_name"`
	ProductVersion string `xml:"product_version"`
	SchemaVersion  string `xml:"schema_version"`
	ContentVersion string `xml:"content_version"`
	Timestamp      string `xml:"timestamp"`
}

type Definitions struct {
	Definition []Definition `xml:"definition"`
}

type Definition struct {
	Class    string   `xml:"class,attr"`
	ID       string   `xml:"id,attr"`
	Version  string   `xml:"version,attr"`
	Metadata Metadata `xml:"metadata"`
	Criteria Criteria `xml:"criteria"`
}

type Metadata struct {
	Title        string      `xml:"title"`
	AffectedList []Affected  `xml:"affected" json:",omitempty"`
	References   []Reference `xml:"reference" json:",omitempty"`
	Description  string      `xml:"description"`
	Advisory     Advisory    `xml:"advisory"`
}

type Advisory struct {
	From            string   `xml:"from,attr"`
	Severity        string   `xml:"severity"`
	Rights          string   `xml:"rights"`
	Issued          Issued   `xml:"issued" json:",omitempty"`
	Updated         Updated  `xml:"updated" json:",omitempty"`
	Cves            []Cve    `xml:"cve" json:",omitempty"`
	Bugzilla        Bugzilla `xml:"bugzilla"`
	AffectedCpeList []string `xml:"affected_cpe_list>cpe" json:",omitempty"`
}

type Criteria struct {
	Operator   string      `xml:"operator,attr"`
	Criterions []Criterion `xml:"criterion" json:",omitempty"`
	Criterias  []Criteria  `xml:"criteria" json:",omitempty"`
}

type Criterion struct {
	Comment string `xml:"comment,attr"`
	TestRef string `xml:"test_ref,attr"`
}

type Affected struct {
	Family    string   `xml:"family,attr"`
	Platforms []string `xml:"platform"`
}

type Reference struct {
	Source string `xml:"source,attr"`
	RefID  string `xml:"ref_id,attr"`
	RefURL string `xml:"ref_url,attr"`
}

type Issued struct {
	Date string `xml:"date,attr"`
}

type Updated struct {
	Date string `xml:"date,attr"`
}

type Cve struct {
	CveID  string `xml:",chardata"`
	Cvss2  string `xml:"cvss2,attr"`
	Cvss3  string `xml:"cvss3,attr"`
	Cwe    string `xml:"cwe,attr"`
	Impact string `xml:"impact,attr"`
	Href   string `xml:"href,attr"`
	Public string `xml:"public,attr"`
}

type Bugzilla struct {
	Href string `xml:"href,attr"`
	ID   string `xml:"id,attr"`
}

type Tests struct {
	RpminfoTests []RpminfoTest `xml:"rpminfo_test"`
}

type Objects struct {
	RpminfoObjects []RpminfoObject `xml:"rpminfo_object"`
}

type States struct {
	RpminfoState []RpminfoState `xml:"rpminfo_state"`
}

type State struct {
	Text     string `xml:",chardata"`
	StateRef string `xml:"state_ref,attr"`
}

type Object struct {
	Text      string `xml:",chardata"`
	ObjectRef string `xml:"object_ref,attr"`
}

type RpminfoTest struct {
	Check          string `xml:"check,attr"`
	Comment        string `xml:"comment,attr"`
	ID             string `xml:"id,attr"`
	Version        string `xml:"version,attr"`
	CheckExistence string `xml:"check_existence,attr"`
	Object         Object `xml:"object"`
	State          State  `xml:"state"`
}

type RpminfoObject struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
	Name    string `xml:"name"`
}

type RpminfoState struct {
	ID             string         `xml:"id,attr"`
	Version        string         `xml:"version,attr"`
	Arch           Arch           `xml:"arch"`
	Evr            Evr            `xml:"evr"`
	SignatureKeyID SignatureKeyID `xml:"signature_keyid"`
}

type SignatureKeyID struct {
	Text      string `xml:",chardata"`
	Operation string `xml:"operation,attr"`
}

type Arch struct {
	Text      string `xml:",chardata"`
	Datatype  string `xml:"datatype,attr"`
	Operation string `xml:"operation,attr"`
}

type Evr struct {
	Text      string `xml:",chardata"`
	Datatype  string `xml:"datatype,attr"`
	Operation string `xml:"operation,attr"`
}
