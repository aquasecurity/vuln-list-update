package alinux

// CSAFDocument represents a CSAF advisory or VEX document
type CSAFDocument struct {
	Document        CSAFDocumentMeta    `json:"document"`
	ProductTree     CSAFProductTree     `json:"product_tree"`
	Vulnerabilities []CSAFVulnerability `json:"vulnerabilities"`
}

// CSAFDocumentMeta holds the document-level metadata
type CSAFDocumentMeta struct {
	AggregateSeverity CSAFAggregateSeverity `json:"aggregate_severity"`
	Category          string                `json:"category"`
	Notes             []CSAFNote            `json:"notes"`
	References        []CSAFReference       `json:"references"`
	Title             string                `json:"title"`
	Tracking          CSAFTracking          `json:"tracking"`
}

// CSAFAggregateSeverity holds the overall severity rating
type CSAFAggregateSeverity struct {
	Text string `json:"text"`
}

// CSAFNote holds advisory notes (summary, description, legal)
type CSAFNote struct {
	Category string `json:"category"`
	Text     string `json:"text"`
	Title    string `json:"title"`
}

// CSAFReference holds reference links
type CSAFReference struct {
	Category string `json:"category"`
	Summary  string `json:"summary"`
	URL      string `json:"url"`
}

// CSAFTracking holds tracking metadata
type CSAFTracking struct {
	CurrentReleaseDate string `json:"current_release_date"`
	ID                 string `json:"id"`
	InitialReleaseDate string `json:"initial_release_date"`
}

// CSAFProductTree holds the product tree with relationships
type CSAFProductTree struct {
	Relationships []CSAFRelationship `json:"relationships"`
}

// CSAFRelationship maps a package (product_reference) to a platform (relates_to_product_reference)
type CSAFRelationship struct {
	Category                  string              `json:"category"`
	FullProductName           CSAFFullProductName `json:"full_product_name"`
	ProductReference          string              `json:"product_reference"`
	RelatesToProductReference string              `json:"relates_to_product_reference"`
}

// CSAFFullProductName identifies the combined product
type CSAFFullProductName struct {
	Name      string `json:"name"`
	ProductID string `json:"product_id"`
}

// CSAFVulnerability represents a vulnerability entry in CSAF
type CSAFVulnerability struct {
	CVE           string             `json:"cve"`
	Notes         []CSAFNote         `json:"notes,omitempty"`
	ProductStatus CSAFProductStatus  `json:"product_status"`
	References    []CSAFReference    `json:"references,omitempty"`
	Remediations  []CSAFRemediation  `json:"remediations,omitempty"`
	Scores        []CSAFScore        `json:"scores,omitempty"`
	Threats       []CSAFThreat       `json:"threats,omitempty"`
	Flags         []CSAFFlag         `json:"flags,omitempty"`
	Title         string             `json:"title,omitempty"`
}

// CSAFProductStatus groups product IDs by their vulnerability status
type CSAFProductStatus struct {
	Fixed            []string `json:"fixed,omitempty"`
	KnownNotAffected []string `json:"known_not_affected,omitempty"`
}

// CSAFScore holds CVSS scoring information
type CSAFScore struct {
	CvssV3   CSAFCvssV3 `json:"cvss_v3"`
	Products []string   `json:"products"`
}

// CSAFCvssV3 holds CVSSv3 score details
type CSAFCvssV3 struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
	Version      string  `json:"version"`
}

// CSAFThreat holds threat/impact information
type CSAFThreat struct {
	Category string `json:"category"`
	Date     string `json:"date"`
	Details  string `json:"details"`
}

// CSAFFlag holds flag information (e.g., vulnerable_code_not_present)
type CSAFFlag struct {
	Label      string   `json:"label"`
	ProductIDs []string `json:"product_ids"`
}

// CSAFRemediation holds remediation information
type CSAFRemediation struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids"`
}
