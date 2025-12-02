package mariner

import "encoding/xml"

type OvalDefinitions struct {
	XMLName        xml.Name    `xml:"oval_definitions" json:",omitempty"`
	Xmlns          string      `xml:"xmlns,attr" json:",omitempty"`
	Oval           string      `xml:"oval,attr" json:",omitempty"`
	LinuxDef       string      `xml:"linux-def,attr" json:",omitempty"`
	Xsi            string      `xml:"xsi,attr" json:",omitempty"`
	SchemaLocation string      `xml:"schemaLocation,attr" json:",omitempty"`
	Generator      Generator   `xml:"generator" json:",omitempty"`
	Definitions    Definitions `xml:"definitions" json:",omitempty"`
	Tests          Tests       `xml:"tests" json:",omitempty"`
	Objects        Objects     `xml:"objects" json:",omitempty"`
	States         States      `xml:"states" json:",omitempty"`
}

type Generator struct {
	ProductName    string `xml:"product_name" json:",omitempty"`
	ProductVersion string `xml:"product_version" json:",omitempty"`
	SchemaVersion  string `xml:"schema_version" json:",omitempty"`
	Timestamp      string `xml:"timestamp" json:",omitempty"`
	ContentVersion string `xml:"content_version" json:",omitempty"`
}

type Metadata struct {
	Title        string    `xml:"title" json:",omitempty"`
	Affected     Affected  `xml:"affected" json:",omitempty"`
	Reference    Reference `xml:"reference" json:",omitempty"`
	Patchable    string    `xml:"patchable" json:",omitempty"`
	AdvisoryDate string    `xml:"advisory_date" json:",omitempty"`
	AdvisoryID   string    `xml:"advisory_id" json:",omitempty"`
	Severity     string    `xml:"severity" json:",omitempty"`
	Description  string    `xml:"description" json:",omitempty"`
}

type Reference struct {
	RefID  string `xml:"ref_id,attr" json:",omitempty"`
	RefURL string `xml:"ref_url,attr" json:",omitempty"`
	Source string `xml:"source,attr" json:",omitempty"`
}

type Affected struct {
	Family   string `xml:"family,attr" json:",omitempty"`
	Platform string `xml:"platform" json:",omitempty"`
}

type Definition struct {
	Class    string   `xml:"class,attr" json:",omitempty"`
	ID       string   `xml:"id,attr" json:",omitempty"`
	Version  string   `xml:"version,attr" json:",omitempty"`
	Metadata Metadata `xml:"metadata" json:",omitempty"`
	Criteria Criteria `xml:"criteria" json:",omitempty"`
}
type Criteria struct {
	Operator  string      `xml:"operator,attr" json:",omitempty"`
	Criterion []Criterion `xml:"criterion" json:",omitempty"`
}

type Criterion struct {
	Comment string `xml:"comment,attr" json:",omitempty"`
	TestRef string `xml:"test_ref,attr" json:",omitempty"`
}

type Definitions struct {
	Definition []Definition `xml:"definition" json:",omitempty"`
}

type Tests struct {
	RpminfoTests []RpminfoTest `xml:"rpminfo_test" json:",omitempty"`
}

type RpminfoTest struct {
	Check   string `xml:"check,attr" json:",omitempty"`
	Comment string `xml:"comment,attr" json:",omitempty"`
	ID      string `xml:"id,attr" json:",omitempty"`
	Version string `xml:"version,attr" json:",omitempty"`
	Object  Object `xml:"object" json:",omitempty"`
	State   State  `xml:"state" json:",omitempty"`
}

type State struct {
	StateRef string `xml:"state_ref,attr" json:",omitempty"`
}

type Object struct {
	ObjectRef string `xml:"object_ref,attr" json:",omitempty"`
}

type Objects struct {
	RpminfoObjects []RpminfoObject `xml:"rpminfo_object" json:",omitempty"`
}

type RpminfoObject struct {
	ID      string `xml:"id,attr" json:",omitempty"`
	Version string `xml:"version,attr" json:",omitempty"`
	Name    string `xml:"name" json:",omitempty"`
}
type States struct {
	RpminfoState []RpminfoState `xml:"rpminfo_state" json:",omitempty"`
}

type RpminfoState struct {
	ID      string `xml:"id,attr" json:",omitempty"`
	Version string `xml:"version,attr" json:",omitempty"`
	Evr     Evr    `xml:"evr" json:",omitempty"`
}

type Evr struct {
	Text      string `xml:",chardata" json:",omitempty"`
	Datatype  string `xml:"datatype,attr" json:",omitempty"`
	Operation string `xml:"operation,attr" json:",omitempty"`
}
