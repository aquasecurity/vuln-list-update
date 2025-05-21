package alt

import "encoding/xml"

type OVALDefinitions struct {
	XMLName   xml.Name  `xml:"oval_definitions"`
	Generator Generator `xml:"generator"`

	Definitions Definitions `xml:"definitions"`
	Tests       Tests       `xml:"tests"`
	Objects     Objects     `xml:"objects"`
	States      States      `xml:"states"`
}

type Generator struct {
	Timestamp     string `xml:"timestamp"`
	ProductName   string `xml:"product_name"`
	SchemaVersion string `xml:"schema_version"`
}

type Definitions struct {
	Definition []Definition `xml:"definition" json:",omitempty"`
}

type Definition struct {
	ID       string   `xml:"id,attr" json:",omitempty"`
	Version  string   `xml:"version,attr" json:",omitempty"`
	Class    string   `xml:"class,attr" json:",omitempty"`
	Metadata Metadata `xml:"metadata" json:",omitempty"`
	Criteria Criteria `xml:"criteria" json:",omitempty"`
}

type Metadata struct {
	Title        string      `xml:"title" json:",omitempty"`
	AffectedList []Affected  `xml:"affected" json:",omitempty"`
	References   []Reference `xml:"reference" json:",omitempty"`
	Description  string      `xml:"description" json:",omitempty"`
	Advisory     Advisory    `xml:"advisory" json:",omitempty"`
}

type Affected struct {
	Family    string   `xml:"family,attr" json:",omitempty"`
	Platforms []string `xml:"platform" json:",omitempty"`
	Products  []string `xml:"product" json:",omitempty"`
}

type Reference struct {
	RefID  string `xml:"ref_id,attr" json:",omitempty"`
	RefURL string `xml:"ref_url,attr" json:",omitempty"`
	Source string `xml:"source,attr" json:",omitempty"`
}

type Advisory struct {
	From         string       `xml:"from,attr" json:",omitempty"`
	Severity     string       `xml:"severity" json:",omitempty"`
	Rights       string       `xml:"rights" json:",omitempty"`
	Issued       Issued       `xml:"issued" json:",omitempty"`
	Updated      Updated      `xml:"updated" json:",omitempty"`
	BDUs         []CVE        `xml:"bdu" json:""`
	CVEs         []CVE        `xml:"cve" json:",omitempty"`
	Bugzilla     []Bugzilla   `xml:"bugzilla" json:",omitempty"`
	AffectedCPEs AffectedCPEs `xml:"affected_cpe_list" json:",omitempty"`
}

type Bugzilla struct {
	ID   string `xml:"id,attr" json:",omitempty"`
	Href string `xml:"href,attr" json:",omitempty"`
	Data string `xml:",chardata" json:",omitempty"`
}

type Issued struct {
	Date string `xml:"date,attr" json:",omitempty"`
}

type Updated struct {
	Date string `xml:"date,attr" json:",omitempty"`
}

type CVE struct {
	ID     string `xml:",chardata"  json:",omitempty"`
	CVSS   string `xml:"cvss,attr" json:",omitempty"`
	CVSS3  string `xml:"cvss3,attr" json:",omitempty"`
	CWE    string `xml:"cwe,attr"   json:",omitempty"`
	Href   string `xml:"href,attr"   json:",omitempty"`
	Impact string `xml:"impact,attr" json:",omitempty"`
	Public string `xml:"public,attr" json:",omitempty"`
}

type AffectedCPEs struct {
	CPEs []string `xml:"cpe" json:",omitempty"`
}

type Criteria struct {
	Operator   string      `xml:"operator,attr" json:",omitempty"`
	Criterions []Criterion `xml:"criterion" json:",omitempty"`
	Criterias  []Criteria  `xml:"criteria" json:",omitempty"`
}

type Criterion struct {
	TestRef string `xml:"test_ref,attr" json:",omitempty"`
	Comment string `xml:"comment,attr" json:",omitempty"`
}

type Tests struct {
	TextFileContent54Tests []TextFileContent54Test `xml:"textfilecontent54_test" json:",omitempty"`
	RPMInfoTests           []RPMInfoTest           `xml:"rpminfo_test" json:",omitempty"`
}

type TextFileContent54Test struct {
	ID      string `xml:"id,attr" json:",omitempty"`
	Version string `xml:"version,attr" json:",omitempty"`
	Check   string `xml:"check,attr" json:",omitempty"`
	Comment string `xml:"comment,attr" json:",omitempty"`
	Object  Object `xml:"object" json:",omitempty"`
	State   State  `xml:"state" json:",omitempty"`
}

type State struct {
	StateRef string `xml:"state_ref,attr" json:",omitempty"`
	Text     string `xml:"state" json:",omitempty"`
}

type Object struct {
	ObjectRef string `xml:"object_ref,attr" json:",omitempty"`
	Text      string `xml:"object" json:",omitempty"`
}

type RPMInfoTest struct {
	ID      string `xml:"id,attr" json:",omitempty"`
	Version string `xml:"version,attr" json:",omitempty"`
	Check   string `xml:"check,attr" json:",omitempty"`
	Comment string `xml:"comment,attr" json:",omitempty"`
	Object  Object `xml:"object" json:",omitempty"`
	State   State  `xml:"state" json:",omitempty"`
}

type RPMInfoObject struct {
	ID      string `xml:"id,attr" json:",omitempty"`
	Version string `xml:"version,attr" json:",omitempty"`
	Comment string `xml:"comment,attr" json:",omitempty"`
	Name    string `xml:"name" json:",omitempty"`
}

type RPMInfoState struct {
	ID            string        `xml:"id,attr" json:",omitempty"`
	Version       string        `xml:"version,attr" json:",omitempty"`
	Comment       string        `xml:"comment,attr" json:",omitempty"`
	Arch          Arch          `xml:"arch" json:",omitempty"`
	EVR           EVR           `xml:"evr" json:",omitempty"`
	Subexpression Subexpression `xml:"subexpression" json:",omitempty"`
}

type Arch struct {
	Text      string `xml:",chardata" json:",omitempty"`
	Datatype  string `xml:"datatype,attr" json:",omitempty"`
	Operation string `xml:"operation,attr" json:",omitempty"`
}

type EVR struct {
	Text      string `xml:",chardata" json:",omitempty"`
	Datatype  string `xml:"datatype,attr" json:",omitempty"`
	Operation string `xml:"operation,attr" json:",omitempty"`
}

type Subexpression struct {
	Operation string `xml:"operation,attr" json:",omitempty"`
	Text      string `xml:",chardata" json:",omitempty"`
}

type Objects struct {
	TextFileContent54Objects []TextFileContent54Object `xml:"textfilecontent54_object" json:",omitempty"`
	RPMInfoObjects           []RPMInfoObject           `xml:"rpminfo_object" json:",omitempty"`
}

type TextFileContent54Object struct {
	ID       string   `xml:"id,attr" json:",omitempty"`
	Version  string   `xml:"version,attr" json:",omitempty"`
	Comment  string   `xml:"comment,attr" json:",omitempty"`
	Path     Path     `xml:"path" json:",omitempty"`
	Filepath Filepath `xml:"filepath" json:",omitempty"`
	Pattern  Pattern  `xml:"pattern" json:",omitempty"`
	Instance Instance `xml:"instance" json:",omitempty"`
}

type Path struct {
	Datatype string `xml:"datatype,attr" json:",omitempty"`
	Text     string `xml:",chardata" json:",omitempty"`
}

type Filepath struct {
	Datatype string `xml:"datatype,attr" json:",omitempty"`
	Text     string `xml:",chardata" json:",omitempty"`
}

type Pattern struct {
	Datatype  string `xml:"datatype,attr" json:",omitempty"`
	Operation string `xml:"operation,attr" json:",omitempty"`
	Text      string `xml:",chardata" json:",omitempty"`
}

type Instance struct {
	Datatype string `xml:"datatype,attr" json:",omitempty"`
	Text     string `xml:",chardata" json:",omitempty"`
}

type Name struct {
	Text      string `xml:",chardata" json:",omitempty"`
	Operation string `xml:"operation,attr" json:",omitempty"`
}

type States struct {
	TextFileContent54State []TextFileContent54State `xml:"textfilecontent54_state" json:",omitempty"`
	RPMInfoStates          []RPMInfoState           `xml:"rpminfo_state" json:",omitempty"`
}

type Version struct {
	Text      string `xml:",chardata" json:",omitempty"`
	Operation string `xml:"operation,attr" json:",omitempty"`
}

type TextFileContent54State struct {
	ID      string `xml:"id,attr" json:",omitempty"`
	Version string `xml:"version,attr" json:",omitempty"`
	Text    Text   `xml:"text" json:",omitempty"`
}

type Text struct {
	Text      string `xml:",chardata" json:",omitempty"`
	Operation string `xml:"operation,attr" json:",omitempty"`
}
