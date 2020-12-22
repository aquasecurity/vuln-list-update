package redhat

import "encoding/xml"

type OvalDefinitions struct {
	XMLName        xml.Name    `xml:"oval_definitions"`
	Xmlns          string      `xml:"xmlns,attr"`
	Oval           string      `xml:"oval,attr"`
	UnixDef        string      `xml:"unix-def,attr"`
	RedDef         string      `xml:"red-def,attr"`
	IndDef         string      `xml:"ind-def,attr"`
	Xsi            string      `xml:"xsi,attr"`
	SchemaLocation string      `xml:"schemaLocation,attr"`
	Generator      Generator   `xml:"generator`
	Definitions    Definitions `xml:"definitions"`

	Tests   Tests   `xml:"tests"`
	Objects Objects `xml:"objects"`
	States  States  `xml:"states"`
}

type Generator struct {
	ProductName    string `xml:"product_name"`
	ProductVersion string `xml:"product_version"`
	SchemaVersion  string `xml:"schema_version"`
	Timestamp      string `xml:"timestamp"`
	ContentVersion string `xml:"content_version"`
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

type Criteria struct {
	Operator   string      `xml:"operator,attr"`
	Criterions []Criterion `xml:"criterion"`
	Criterias  []Criteria  `xml:"criteria"`
}

type Criterion struct {
	Comment string `xml:"comment,attr"`
	TestRef string `xml:"test_ref,attr"`
}

type Metadata struct {
	Title       string      `xml:"title"`
	Affected    []Affected  `xml:"affected"`
	References  []Reference `xml:"reference"`
	Description string      `xml:"description"`
	Advisory    Advisory    `xml:"advisory"`
}
type Advisory struct {
	From            string          `xml:"from,attr"`
	Severity        string          `xml:"severity"`
	Rights          string          `xml:"rights"`
	Issued          Issued          `xml:"issued"`
	Updated         Updated         `xml:"updated"`
	Cves            []Cve           `xml:"cve"`
	Bugzilla        Bugzilla        `xml:"bugzilla"`
	AffectedCpeList AffectedCpeList `xml:"affected_cpe_list"`
}

type Affected struct {
	Family   string `xml:"family,attr"`
	Platform string `xml:"platform"`
}

type Reference struct {
	RefID  string `xml:"ref_id,attr"`
	RefURL string `xml:"ref_url,attr"`
	Source string `xml:"source,attr"`
}

type Issued struct {
	Date string `xml:"date,attr"`
}

type Updated struct {
	Date string `xml:"date,attr"`
}

type Cve struct {
	Cvss3  string `xml:"cvss3,attr"`
	Cwe    string `xml:"cwe,attr"`
	Href   string `xml:"href,attr"`
	Public string `xml:"public,attr"`
	Impact string `xml:"impact,attr"`
}

type Bugzilla struct {
	Href string `xml:"href,attr"`
	ID   string `xml:"id,attr"`
}

type AffectedCpeList struct {
	Cpe []string `xml:"cpe"`
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
	StateRef string `xml:"state_ref,attr"`
}

type Object struct {
	ObjectRef string `xml:"object_ref,attr"`
}

type RpminfoTest struct {
	Text           string `xml:",chardata"`
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
	Operation string `xml:"operation,attr"`
}

type Arch struct {
	Datatype  string `xml:"datatype,attr"`
	Operation string `xml:"operation,attr"`
}

type Evr struct {
	Datatype  string `xml:"datatype,attr"`
	Operation string `xml:"operation,attr"`
}
