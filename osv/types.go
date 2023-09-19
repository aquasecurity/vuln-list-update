package osv

type Affected struct {
	Package    Package     `json:"package,omitempty"`
	Severities []Severity  `json:"severity,omitempty"`
	Ranges     []Range     `json:"ranges,omitempty"`
	Versions   []string    `json:"versions,omitempty"`
	Ecosystem  interface{} `json:"ecosystem_specific,omitempty"` //The meaning of the values within the object is entirely defined by the ecosystem
	Database   interface{} `json:"database_specific,omitempty"`  //The meaning of the values within the object is entirely defined by the database

}

type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type Package struct {
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	Purl      string `json:"purl,omitempty"`
}
type Range struct {
	Type   string  `json:"type,omitempty"`
	Repo   string  `json:"repo,omitempty"`
	Events []Event `json:"events,omitempty"`
}
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type Reference struct {
	Type string `json:"type,omitempty"`
	Url  string `json:"url,omitempty"`
}

// OSV represents Open Source Vulnerability format
// ref. https://ossf.github.io/osv-schema
type OSV struct {
	ID         string      `json:"id,omitempty"`
	Modified   string      `json:"modified,omitempty"`
	Published  string      `json:"published,omitempty"`
	Withdrawn  string      `json:"withdrawn,omitempty"`
	Aliases    []string    `json:"aliases,omitempty"`
	Related    []string    `json:"related,omitempty"`
	Summary    string      `json:"summary,omitempty"`
	Details    string      `json:"details,omitempty"`
	Affected   []Affected  `json:"affected,omitempty"` //collection based on https://ossf.github.io/osv-schema/
	References []Reference `json:"references,omitempty"`
}
