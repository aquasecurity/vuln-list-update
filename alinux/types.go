package alinux

import "encoding/xml"

// OvalDefinitions represents the root element of an OVAL XML document
type OvalDefinitions struct {
	XMLName     xml.Name     `xml:"oval_definitions"`
	Definitions []Definition `xml:"definitions>definition"`
	Tests       Tests        `xml:"tests"`
	Objects     Objects      `xml:"objects"`
	States      States       `xml:"states"`
}

// Definition represents an OVAL definition (security advisory)
type Definition struct {
	ID       string   `xml:"id,attr"`
	Class    string   `xml:"class,attr"`
	Metadata Metadata `xml:"metadata"`
	Criteria Criteria `xml:"criteria"`
}

// Metadata contains advisory metadata
type Metadata struct {
	Title     string    `xml:"title"`
	Affected  Affected  `xml:"affected"`
	Reference Reference `xml:"reference"`
	Desc      string    `xml:"description"`
	Advisory  Advisory  `xml:"advisory"`
}

// Affected has platform info
type Affected struct {
	Family   string `xml:"family,attr"`
	Platform string `xml:"platform"`
}

// Reference has the advisory reference
type Reference struct {
	RefID  string `xml:"ref_id,attr"`
	RefURL string `xml:"ref_url,attr"`
	Source string `xml:"source,attr"`
}

// Advisory contains detailed advisory info
type Advisory struct {
	From            string `xml:"from,attr"`
	Severity        string `xml:"severity"`
	Rights          string `xml:"rights"`
	Issued          Date   `xml:"issued"`
	Updated         Date   `xml:"updated"`
	Cves            []Cve  `xml:"cve"`
	AffectedCPEList []string `xml:"affected_cpe_list>cpe"`
}

// Cve contains CVE details
type Cve struct {
	CveID  string `xml:",chardata"`
	Cvss3  string `xml:"cvss3,attr"`
	Impact string `xml:"impact,attr"`
	Cwe    string `xml:"cwe,attr"`
	Href   string `xml:"href,attr"`
	Public string `xml:"public,attr"`
}

// Date has a date attribute
type Date struct {
	Date string `xml:"date,attr"`
}

// Criteria contains test criteria
type Criteria struct {
	Operator   string      `xml:"operator,attr"`
	Criterions []Criterion `xml:"criterion"`
	Criterias  []Criteria  `xml:"criteria"`
}

// Criterion is a single test condition
type Criterion struct {
	TestRef string `xml:"test_ref,attr"`
	Comment string `xml:"comment,attr"`
}

// Tests section
type Tests struct {
	RPMInfoTests           []RPMInfoTest           `xml:"rpminfo_test"`
	TextFileContent54Tests []TextFileContent54Test  `xml:"textfilecontent54_test"`
}

// RPMInfoTest represents an RPM package version test
type RPMInfoTest struct {
	ID        string    `xml:"id,attr"`
	Comment   string    `xml:"comment,attr"`
	Check     string    `xml:"check,attr"`
	ObjectRef ObjectRef `xml:"object"`
	StateRef  StateRef  `xml:"state"`
}

// TextFileContent54Test represents a text file content test
type TextFileContent54Test struct {
	ID        string    `xml:"id,attr"`
	Comment   string    `xml:"comment,attr"`
	ObjectRef ObjectRef `xml:"object"`
	StateRef  StateRef  `xml:"state"`
}

// ObjectRef references an object
type ObjectRef struct {
	Ref string `xml:"object_ref,attr"`
}

// StateRef references a state
type StateRef struct {
	Ref string `xml:"state_ref,attr"`
}

// Objects section
type Objects struct {
	RPMInfoObjects []RPMInfoObject `xml:"rpminfo_object"`
}

// RPMInfoObject contains the package name
type RPMInfoObject struct {
	ID   string `xml:"id,attr"`
	Name string `xml:"name"`
}

// States section
type States struct {
	RPMInfoStates []RPMInfoState `xml:"rpminfo_state"`
}

// RPMInfoState contains version comparison info
type RPMInfoState struct {
	ID  string `xml:"id,attr"`
	EVR EVR    `xml:"evr"`
}

// EVR contains epoch:version-release info
type EVR struct {
	Datatype  string `xml:"datatype,attr"`
	Operation string `xml:"operation,attr"`
	Value     string `xml:",chardata"`
}

// ALSA represents a simplified Alinux Security Advisory for JSON output
type ALSA struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Severity    string     `json:"severity"`
	Description string     `json:"description"`
	Issued      DateJSON   `json:"issued"`
	Updated     DateJSON   `json:"updated"`
	Packages    []Package  `json:"packages"`
	CveIDs      []string   `json:"cveids"`
	References  []CveRef   `json:"references"`
}

// DateJSON wraps a date string for JSON output
type DateJSON struct {
	Date string `json:"date"`
}

// Package has affected package information
type Package struct {
	Name    string `json:"name"`
	Epoch   string `json:"epoch"`
	Version string `json:"version"`
	Release string `json:"release"`
}

// CveRef has CVE reference information
type CveRef struct {
	ID     string `json:"id"`
	Href   string `json:"href"`
	Cvss3  string `json:"cvss3,omitempty"`
	Impact string `json:"impact,omitempty"`
}
