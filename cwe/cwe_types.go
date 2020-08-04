// This was partially auto-generated through: https://github.com/droyo/go-xml
// Schema: https://cwe.mitre.org/data/xsd/cwe_schema_latest.xsd

package cwe

import (
	"encoding/xml"
)

type RelatedAttackPattern struct {
	CAPECID int `xml:"CAPEC_ID,attr"`
}

// The RelatedAttackPatternsType complex type contains references to attack patterns associated with this weakness. The association implies those attack patterns may be applicable if an instance of this weakness exists. Each related attack pattern is identified by a CAPEC identifier.
type RelatedAttackPatternsType struct {
	RelatedAttackPattern []RelatedAttackPattern `xml:"http://cwe.mitre.org/cwe-6 Related_Attack_Pattern"`
}

type Mitigation struct {
	Phase       []PhaseEnumeration            `xml:"http://cwe.mitre.org/cwe-6 Phase,omitempty"`
	Strategy    MitigationStrategyEnumeration `xml:"http://cwe.mitre.org/cwe-6 Strategy,omitempty"`
	Description StructuredTextType            `xml:"http://cwe.mitre.org/cwe-6 Description"`
}

// May be one of Policy, Requirements, Architecture and Design, Implementation, Build and Compilation, Testing, Documentation, Bundling, Distribution, Installation, System Configuration, Operation, Patching and Maintenance, Porting, Integration, Manufacturing
type PhaseEnumeration string

// May be one of Attack Surface Reduction, Compilation or Build Hardening, Enforcement by Conversion, Environment Hardening, Firewall, Input Validation, Language Selection, Libraries or Frameworks, Resource Limitation, Output Encoding, Parameterization, Refactoring, Sandbox or Jail, Separation of Privilege
type MitigationStrategyEnumeration string

// The PotentialMitigationsType complex type is used to describe potential mitigations associated with a weakness. It contains one or more Mitigation elements, which each represent individual mitigations for the weakness. The Phase element indicates the development life cycle phase during which this particular mitigation may be applied. The Strategy element describes a general strategy for protecting a system to which this mitigation contributes. The Effectiveness element summarizes how effective the mitigation may be in preventing the weakness. The Description element contains a description of this individual mitigation including any strengths and shortcomings of this mitigation for the weakness.
//
// The optional Mitigation_ID attribute is used by the internal CWE team to uniquely identify mitigations that are repeated across any number of individual weaknesses. To help make sure that the details of these common mitigations stay synchronized, the Mitigation_ID is used to quickly identify those mitigation elements across CWE that should be identical. The identifier is a string and should match the following format: MIT-1.
type PotentialMitigationsType struct {
	Mitigation []Mitigation `xml:"http://cwe.mitre.org/cwe-6 Mitigation"`
}

// The CommonConsequencesType complex type is used to specify individual consequences associated with a weakness. The required Scope element identifies the security property that is violated. The optional Impact element describes the technical impact that arises if an adversary succeeds in exploiting this weakness. The optional Likelihood element identifies how likely the specific consequence is expected to be seen relative to the other consequences. For example, there may be high likelihood that a weakness will be exploited to achieve a certain impact, but a low likelihood that it will be exploited to achieve a different impact. The optional Note element provides additional commentary about a consequence.
//
// The optional Consequence_ID attribute is used by the internal CWE team to uniquely identify examples that are repeated across any number of individual weaknesses. To help make sure that the details of these common examples stay synchronized, the Consequence_ID is used to quickly identify those examples across CWE that should be identical. The identifier is a string and should match the following format: CC-1.
type CommonConsequencesType struct {
	Consequence []Consequence `xml:"http://cwe.mitre.org/cwe-6 Consequence"`
}

type Consequence struct {
	Scope  []ScopeEnumeration           `xml:"http://cwe.mitre.org/cwe-6 Scope"`
	Impact []TechnicalImpactEnumeration `xml:"http://cwe.mitre.org/cwe-6 Impact,omitempty"`
}

// May be one of Modify Memory, Read Memory, Modify Files or Directories, Read Files or Directories, Modify Application Data, Read Application Data, DoS: Crash, Exit, or Restart, DoS: Amplification, DoS: Instability, DoS: Resource Consumption (CPU), DoS: Resource Consumption (Memory), DoS: Resource Consumption (Other), Execute Unauthorized Code or Commands, Gain Privileges or Assume Identity, Bypass Protection Mechanism, Hide Activities, Alter Execution Logic, Quality Degradation, Unexpected State, Varies by Context, Reduce Maintainability, Reduce Performance, Reduce Reliability, Other
type TechnicalImpactEnumeration string

// May be one of Confidentiality, Integrity, Availability, Access Control, Accountability, Authentication, Authorization, Non-Repudiation, Other
type ScopeEnumeration string
type StructuredTextType []string

func (a StructuredTextType) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	var output struct {
		ArrayType string   `xml:"http://schemas.xmlsoap.org/wsdl/ arrayType,attr"`
		Items     []string `xml:"item"`
	}
	output.Items = []string(a)
	start.Attr = append(start.Attr, xml.Attr{Name: xml.Name{Space: " ", Local: "xmlns:ns1"}, Value: "http://www.w3.org/2001/XMLSchema"})
	output.ArrayType = "ns1:anyType[]"
	return e.EncodeElement(&output, start)
}
func (a *StructuredTextType) UnmarshalXML(d *xml.Decoder, start xml.StartElement) (err error) {
	var tok xml.Token
	for tok, err = d.Token(); err == nil; tok, err = d.Token() {
		if tok, ok := tok.(xml.StartElement); ok {
			var item string
			if err = d.DecodeElement(&item, &tok); err == nil {
				*a = append(*a, item)
			}
		}
		if _, ok := tok.(xml.EndElement); ok {
			break
		}
	}
	return err
}

type WeaknessCatalog struct {
	Weaknesses Weaknesses `xml:"http://cwe.mitre.org/cwe-6 Weaknesses,omitempty"`
}

func (t *WeaknessCatalog) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type T WeaknessCatalog
	var layout struct {
		*T
	}
	layout.T = (*T)(t)
	return e.EncodeElement(layout, start)
}
func (t *WeaknessCatalog) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type T WeaknessCatalog
	var overlay struct {
		*T
	}
	overlay.T = (*T)(t)
	return d.DecodeElement(&overlay, &start)
}

type WeaknessType struct {
	ID                    int                       `xml:"ID,attr"`
	Name                  string                    `xml:"Name,attr"`
	Description           string                    `xml:"http://cwe.mitre.org/cwe-6 Description"`
	PotentialMitigations  PotentialMitigationsType  `xml:"http://cwe.mitre.org/cwe-6 Potential_Mitigations,omitempty"`
	RelatedAttackPatterns RelatedAttackPatternsType `xml:"http://cwe.mitre.org/cwe-6 Related_Attack_Patterns,omitempty"`
	CommonConsequences    CommonConsequencesType    `xml:"http://cwe.mitre.org/cwe-6 Common_Consequences,omitempty"`
	ExtendedDescription   StructuredTextType        `xml:"http://cwe.mitre.org/cwe-6 Extended_Description,omitempty"`
}

type Weaknesses struct {
	Weakness []WeaknessType `xml:"http://cwe.mitre.org/cwe-6 Weakness"`
}
