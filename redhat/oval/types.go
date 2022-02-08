package oval

import (
	"encoding/xml"
)

type OvalDefinitions struct {
	XMLName     xml.Name    `xml:"oval_definitions"`
	Generator   Generator   `xml:"generator"`
	Definitions Definitions `xml:"definitions"`

	Tests   Tests   `xml:"tests" json:",omitempty"`
	Objects Objects `xml:"objects" json:",omitempty"`
	States  States  `xml:"states" json:",omitempty"`
}

type Generator struct {
	ProductName    string `xml:"product_name"`
	ProductVersion string `xml:"product_version"`
	SchemaVersion  string `xml:"schema_version"`
	ContentVersion string `xml:"content_version"`
	Timestamp      string `xml:"timestamp"`
}

type Definitions struct {
	Definition []Definition `xml:"definition" json:",omitempty"`
}

type Definition struct {
	Class    string   `xml:"class,attr" json:",omitempty"`
	ID       string   `xml:"id,attr" json:",omitempty"`
	Version  string   `xml:"version,attr" json:",omitempty"`
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

type Advisory struct {
	From            string      `xml:"from,attr" json:",omitempty"`
	Severity        string      `xml:"severity" json:",omitempty"`
	Rights          string      `xml:"rights" json:",omitempty"`
	Issued          Issued      `xml:"issued" json:",omitempty"`
	Updated         Updated     `xml:"updated" json:",omitempty"`
	Cves            []Cve       `xml:"cve" json:",omitempty"`
	Bugzilla        []Bugzilla  `xml:"bugzilla" json:",omitempty"`
	AffectedCpeList []string    `xml:"affected_cpe_list>cpe" json:",omitempty"`
	Affected        AdvAffected `xml:"affected" json:",omitempty"`
}

type AdvAffected struct {
	Resolution Resolution `xml:"resolution" json:",omitempty"`
}

type Criteria struct {
	Operator   string      `xml:"operator,attr" json:",omitempty"`
	Criterions []Criterion `xml:"criterion" json:",omitempty"`
	Criterias  []Criteria  `xml:"criteria" json:",omitempty"`
}

type Criterion struct {
	Comment string `xml:"comment,attr"`
	TestRef string `xml:"test_ref,attr"`
}

type Affected struct {
	Family    string   `xml:"family,attr" json:",omitempty"`
	Platforms []string `xml:"platform" json:",omitempty"`
}

type Resolution struct {
	State string `xml:"state,attr" json:",omitempty"`
}

type Reference struct {
	Source string `xml:"source,attr" json:",omitempty"`
	RefID  string `xml:"ref_id,attr" json:",omitempty"`
	RefURL string `xml:"ref_url,attr" json:",omitempty"`
}

type Issued struct {
	Date string `xml:"date,attr" json:",omitempty"`
}

type Updated struct {
	Date string `xml:"date,attr" json:",omitempty"`
}

type Cve struct {
	CveID  string `xml:",chardata" json:",omitempty"`
	Cvss2  string `xml:"cvss2,attr" json:",omitempty"`
	Cvss3  string `xml:"cvss3,attr" json:",omitempty"`
	Cwe    string `xml:"cwe,attr" json:",omitempty"`
	Impact string `xml:"impact,attr" json:",omitempty"`
	Href   string `xml:"href,attr" json:",omitempty"`
	Public string `xml:"public,attr" json:",omitempty"`
}

type Bugzilla struct {
	Href string `xml:"href,attr" json:",omitempty"`
	ID   string `xml:"id,attr" json:",omitempty"`
}

type State struct {
	Text     string `xml:",chardata" json:",omitempty"`
	StateRef string `xml:"state_ref,attr" json:",omitempty"`
}

type Object struct {
	Text      string `xml:",chardata" json:",omitempty"`
	ObjectRef string `xml:"object_ref,attr" json:",omitempty"`
}

type RpminfoTest struct {
	Check          string `xml:"check,attr" json:",omitempty"`
	Comment        string `xml:"comment,attr" json:",omitempty"`
	ID             string `xml:"id,attr" json:",omitempty"`
	Version        string `xml:"version,attr" json:",omitempty"`
	CheckExistence string `xml:"check_existence,attr" json:",omitempty"`
	Object         Object `xml:"object" json:",omitempty"`
	State          State  `xml:"state" json:",omitempty"`
}

type RpminfoObject struct {
	ID      string `xml:"id,attr" json:",omitempty"`
	Version string `xml:"version,attr" json:",omitempty"`
	Name    string `xml:"name" json:",omitempty"`
}

type RpminfoState struct {
	ID             string         `xml:"id,attr" json:",omitempty"`
	Version        string         `xml:"version,attr" json:",omitempty"`
	Arch           Arch           `xml:"arch" json:",omitempty"`
	Evr            Evr            `xml:"evr" json:",omitempty"`
	SignatureKeyID SignatureKeyID `xml:"signature_keyid" json:",omitempty"`
}

type SignatureKeyID struct {
	Text      string `xml:",chardata" json:",omitempty"`
	Operation string `xml:"operation,attr" json:",omitempty"`
}

type Arch struct {
	Text      string `xml:",chardata" json:",omitempty"`
	Datatype  string `xml:"datatype,attr" json:",omitempty"`
	Operation string `xml:"operation,attr" json:",omitempty"`
}

type Evr struct {
	Text      string `xml:",chardata" json:",omitempty"`
	Datatype  string `xml:"datatype,attr" json:",omitempty"`
	Operation string `xml:"operation,attr" json:",omitempty"`
}

type Tests struct {
	RpminfoTests           []RpminfoTest           `xml:"rpminfo_test" json:",omitempty"`
	RpmverifyfileTests     []RpmverifyfileTest     `xml:"rpmverifyfile_test" json:",omitempty"`
	Textfilecontent54Tests []Textfilecontent54Test `xml:"textfilecontent54_test" json:",omitempty"`
	UnameTests             []UnameTest             `xml:"uname_test" json:",omitempty"`
}

type Textfilecontent54Test struct {
	Check   string `xml:"check,attr" json:",omitempty"`
	Comment string `xml:"comment,attr" json:",omitempty"`
	ID      string `xml:"id,attr" json:",omitempty"`
	Version string `xml:"version,attr" json:",omitempty"`
	Object  Object `xml:"object" json:",omitempty"`
	State   State  `xml:"state" json:",omitempty"`
}

type RpmverifyfileTest struct {
	Check   string `xml:"check,attr" json:",omitempty"`
	Comment string `xml:"comment,attr" json:",omitempty"`
	ID      string `xml:"id,attr" json:",omitempty"`
	Version string `xml:"version,attr" json:",omitempty"`
	Object  Object `xml:"object" json:",omitempty"`
	State   State  `xml:"state" json:",omitempty"`
}

type UnameTest struct {
	Check   string `xml:"check,attr" json:",omitempty"`
	Comment string `xml:"comment,attr" json:",omitempty"`
	ID      string `xml:"id,attr" json:",omitempty"`
	Version string `xml:"version,attr" json:",omitempty"`
	Object  Object `xml:"object" json:",omitempty"`
	State   State  `xml:"state" json:",omitempty"`
}

type Objects struct {
	RpminfoObjects           []RpminfoObject           `xml:"rpminfo_object" json:",omitempty"`
	RpmverifyfileObjects     []RpmverifyfileObject     `xml:"rpmverifyfile_object" json:",omitempty"`
	Textfilecontent54Objects []Textfilecontent54Object `xml:"textfilecontent54_object" json:",omitempty"`
	UnameObjects             []UnameObject             `xml:"uname_object" json:",omitempty"`
}

type UnameObject struct {
	Text    string `xml:",chardata" json:",omitempty"`
	ID      string `xml:"id,attr" json:",omitempty"`
	Version string `xml:"version,attr" json:",omitempty"`
}

type Filepath struct {
	Text     string `xml:",chardata" json:",omitempty"`
	Datatype string `xml:"datatype,attr" json:",omitempty"`
}

type Pattern struct {
	Text      string `xml:",chardata" json:",omitempty"`
	Operation string `xml:"operation,attr" json:",omitempty"`
}

type Instance struct {
	Text     string `xml:",chardata" json:",omitempty"`
	Datatype string `xml:"datatype,attr" json:",omitempty"`
	VarRef   string `xml:"var_ref,attr" json:",omitempty"`
}

type Textfilecontent54Object struct {
	ID       string   `xml:"id,attr" json:",omitempty"`
	Version  string   `xml:"version,attr" json:",omitempty"`
	Filepath Filepath `xml:"filepath" json:",omitempty"`
	Pattern  Pattern  `xml:"pattern" json:",omitempty"`
	Instance Instance `xml:"instance" json:",omitempty"`
}
type Behaviors struct {
	Text          string `xml:",chardata" json:",omitempty"`
	Noconfigfiles string `xml:"noconfigfiles,attr" json:",omitempty"`
	Noghostfiles  string `xml:"noghostfiles,attr" json:",omitempty"`
	Nogroup       string `xml:"nogroup,attr" json:",omitempty"`
	Nolinkto      string `xml:"nolinkto,attr" json:",omitempty"`
	Nomd5         string `xml:"nomd5,attr" json:",omitempty"`
	Nomode        string `xml:"nomode,attr" json:",omitempty"`
	Nomtime       string `xml:"nomtime,attr" json:",omitempty"`
	Nordev        string `xml:"nordev,attr" json:",omitempty"`
	Nosize        string `xml:"nosize,attr" json:",omitempty"`
	Nouser        string `xml:"nouser,attr" json:",omitempty"`
}

type RpmverifyfileObject struct {
	ID          string    `xml:"id,attr" json:",omitempty"`
	AttrVersion string    `xml:"version,attr" json:",omitempty"`
	Behaviors   Behaviors `xml:"behaviors" json:",omitempty"`
	Filepath    Filepath  `xml:"filepath" json:",omitempty"`
	Name        Name      `xml:"name" json:",omitempty"`
	Version     Version   `xml:"version" json:",omitempty"`
	Epoch       Epoch     `xml:"epoch" json:",omitempty"`
	Arch        Arch      `xml:"arch" json:",omitempty"`
	Release     Release   `xml:"release" json:",omitempty"`
}
type Epoch struct {
	Text      string `xml:",chardata" json:",omitempty"`
	Operation string `xml:"operation,attr" json:",omitempty"`
}

type Release struct {
	Text      string `xml:",chardata" json:",omitempty"`
	Operation string `xml:"operation,attr" json:",omitempty"`
}
type Name struct {
	Text      string `xml:",chardata" json:",omitempty"`
	Operation string `xml:"operation,attr" json:",omitempty"`
}

type States struct {
	RpminfoState           []RpminfoState           `xml:"rpminfo_state" json:",omitempty"`
	RpmverifyfileStates    []RpmverifyfileState     `xml:"rpmverifyfile_state" json:",omitempty"`
	Textfilecontent54State []Textfilecontent54State `xml:"textfilecontent54_state" json:",omitempty"`
	UnameState             []UnameState             `xml:"uname_state" json:",omitempty"`
}

type Version struct {
	Text      string `xml:",chardata" json:",omitempty"`
	Operation string `xml:"operation,attr" json:",omitempty"`
}

type RpmverifyfileState struct {
	ID          string  `xml:"id,attr" json:",omitempty"`
	AttrVersion string  `xml:"version,attr" json:",omitempty"`
	Name        Name    `xml:"name" json:",omitempty"`
	Version     Version `xml:"version" json:",omitempty"`
}

type Textfilecontent54State struct {
	ID      string `xml:"id,attr" json:",omitempty"`
	Version string `xml:"version,attr" json:",omitempty"`
	Text    Text   `xml:"text" json:",omitempty"`
}

type Text struct {
	Text      string `xml:",chardata" json:",omitempty"`
	Operation string `xml:"operation,attr" json:",omitempty"`
}

type OsRelease struct {
	Text      string `xml:",chardata" json:",omitempty"`
	Operation string `xml:"operation,attr" json:",omitempty"`
}

type UnameState struct {
	ID        string    `xml:"id,attr" json:",omitempty"`
	Version   string    `xml:"version,attr" json:",omitempty"`
	OsRelease OsRelease `xml:"os_release" json:",omitempty"`
}

type repositoryToCPE struct {
	Data map[string]struct {
		Cpes []string `json:"cpes"`
	} `json:"data"`
}
