package types

type OsvPackage struct {
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	Purl      string `json:"purl,omitempty"`
}
type OsvRange struct {
	Type       string `json:"type,omitempty"`
	Repo       string `json:"repo,omitempty"`
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}
type OsvScope struct {
	Ranges   []OsvRange `json:"ranges,omitempty"`
	Versions []string   `json:"versions,omitempty"`
}
type OsvReference struct {
	Type string `json:"type,omitempty"`
	Url  string `json:"url,omitempty"`
}

type Osv struct {
	Id         string         `json:"id,omitempty"`
	Modified   string         `json:"modified,omitempty"`
	Published  string         `json:"published,omitempty"`
	Withdrawn  string         `json:"withdrawn,omitempty"`
	Aliases    []string       `json:"aliases,omitempty"`
	Related    []string       `json:"related,omitempty"`
	Package    *OsvPackage    `json:"package,omitempty"`
	Summary    string         `json:"summary,omitempty"`
	Details    string         `json:"details,omitempty"`
	Affects    OsvScope       `json:"affects,omitempty"` //TODO could be collection based on https://security.googleblog.com/2021/06/announcing-unified-vulnerability-schema.html
	References []OsvReference `json:"references,omitempty"`

	// TODO	"ecosystem_specific": { see spec },

	// TODO	"database_specific": { see spec },

}
