package amazon

// RepoMd has repomd data
type RepoMd struct {
	RepoList []Repo `xml:"data"`
}

// Repo has a repo data
type Repo struct {
	Type     string   `xml:"type,attr"`
	Location Location `xml:"location"`
}

// Location has a location of repomd
type Location struct {
	Href string `xml:"href,attr"`
}

// UpdateInfo has a list of ALAS
type UpdateInfo struct {
	ALASList []ALAS `xml:"update"`
}

// ALAS has detailed data of ALAS
type ALAS struct {
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

// Updated has updated at
type Date struct {
	Date string `xml:"date,attr" json:"date,omitempty"`
}

// Reference has reference information
type Reference struct {
	Href  string `xml:"href,attr" json:"href,omitempty"`
	ID    string `xml:"id,attr" json:"id,omitempty"`
	Title string `xml:"title,attr" json:"title,omitempty"`
	Type  string `xml:"type,attr" json:"type,omitempty"`
}

// Package has affected package information
type Package struct {
	Name     string `xml:"name,attr" json:"name,omitempty"`
	Epoch    string `xml:"epoch,attr" json:"epoch,omitempty"`
	Version  string `xml:"version,attr" json:"version,omitempty"`
	Release  string `xml:"release,attr" json:"release,omitempty"`
	Arch     string `xml:"arch,attr" json:"arch,omitempty"`
	Filename string `xml:"filename" json:"filename,omitempty"`
}

// Root has list of releases
type Root struct {
	Releases Releases `xml:"releases"`
}

type Releases struct {
	Release []Release `xml:"release"`
}

type Release struct {
	Version string `xml:"version,attr"`
}
