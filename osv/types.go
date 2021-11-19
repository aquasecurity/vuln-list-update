package osv

type OsvAffected struct {
	Package  *OsvPackage `json:"package,omitempty"`
	Ranges   []OsvRange  `json:"ranges,omitempty"`
	Versions []string    `json:"versions,omitempty"`

	// Ecosystem *OsvEcosystem `json:"ecosystem_specific,omitempty"` //The meaning of the values within the object is entirely defined by the ecosystem

	// Database  *OsvDatabase  `json:"database_specific,omitempty"` //The meaning of the values within the object is entirely defined by the database

}
type OsvPackage struct {
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	Purl      string `json:"purl,omitempty"`
}
type OsvRange struct {
	Type   string     `json:"type,omitempty"`
	Repo   string     `json:"repo,omitempty"`
	Events []OsvEvent `json:"events,omitempty"`
}
type OsvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// type OsvEcosystem struct {
// }

// type OsvDatabase struct {
// }

type OsvReference struct {
	Type string `json:"type,omitempty"`
	Url  string `json:"url,omitempty"`
}

type OsvJson struct {
	Id         string         `json:"id,omitempty"`
	Modified   string         `json:"modified,omitempty"`
	Published  string         `json:"published,omitempty"`
	Withdrawn  string         `json:"withdrawn,omitempty"`
	Aliases    []string       `json:"aliases,omitempty"`
	Related    []string       `json:"related,omitempty"`
	Summary    string         `json:"summary,omitempty"`
	Details    string         `json:"details,omitempty"`
	Affected   []OsvAffected  `json:"affected,omitempty"` //collection based on https://ossf.github.io/osv-schema/
	References []OsvReference `json:"references,omitempty"`
}
