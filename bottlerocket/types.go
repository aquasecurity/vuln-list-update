package bottlerocket

// UpdateInfo represents the top-level structure of the updateinfo.xml file
type UpdateInfo struct {
	Updates []Update `xml:"update"`
}

// Update represents a single security advisory entry
type Update struct {
	ID          string      `xml:"id" json:"id,omitempty"`
	Title       string      `xml:"title" json:"title,omitempty"`
	Issued      Date        `xml:"issued" json:"issued,omitempty"`
	Updated     Date        `xml:"updated" json:"updated,omitempty"`
	Severity    string      `xml:"severity" json:"severity,omitempty"`
	Description string      `xml:"description" json:"description,omitempty"`
	Packages    []Package   `xml:"pkglist>collection>package" json:"packages,omitempty"`
	References  []Reference `xml:"references>reference" json:"references,omitempty"`
	CveIDs      []string    `json:"cveids,omitempty"`
}

// Date holds an advisory timestamp
type Date struct {
	Date string `xml:"date,attr" json:"date,omitempty"`
}

// Reference holds a vulnerability reference (CVE, GHSA, BRSA, etc.)
type Reference struct {
	Href string `xml:"href,attr" json:"href,omitempty"`
	ID   string `xml:"id,attr" json:"id,omitempty"`
	Type string `xml:"type,attr" json:"type,omitempty"`
}

// Package holds information about an affected/fixed package
type Package struct {
	Name    string `xml:"name,attr" json:"name,omitempty"`
	Epoch   string `xml:"epoch,attr" json:"epoch,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	Release string `xml:"release,attr" json:"release,omitempty"`
	Arch    string `xml:"arch,attr" json:"arch,omitempty"`
}
