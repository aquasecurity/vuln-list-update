package ghsa

import (
	"encoding/json"
	"time"
)

type RangeType string

type Ecosystem string

type Module struct {
	Path      string    `json:"name"`
	Ecosystem Ecosystem `json:"ecosystem"`
}

type RangeEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type Range struct {
	Type   RangeType    `json:"type"`
	Events []RangeEvent `json:"events"`
}

type ReferenceType string

type Reference struct {
	Type ReferenceType `json:"type"`
	URL  string        `json:"url"`
}

type Affected struct {
	Module            Module             `json:"package"`
	Ranges            []Range            `json:"ranges,omitempty"`
	EcosystemSpecific *EcosystemSpecific `json:"ecosystem_specific,omitempty"`
}

type Package struct {
	Path    string   `json:"path"`
	GOOS    []string `json:"goos,omitempty"`
	GOARCH  []string `json:"goarch,omitempty"`
	Symbols []string `json:"symbols,omitempty"`
}

type EcosystemSpecific struct {
	Packages []Package `json:"imports,omitempty"`
}

type Entry struct {
	SchemaVersion    string            `json:"schema_version,omitempty"`
	ID               string            `json:"id"`
	Modified         Time              `json:"modified,omitempty"`
	Published        Time              `json:"published,omitempty"`
	Withdrawn        *Time             `json:"withdrawn,omitempty"`
	Aliases          []string          `json:"aliases,omitempty"`
	Summary          string            `json:"summary,omitempty"`
	Details          string            `json:"details"`
	Affected         []Affected        `json:"affected"`
	References       []Reference       `json:"references,omitempty"`
	Credits          []Credit          `json:"credits,omitempty"`
	DatabaseSpecific *DatabaseSpecific `json:"database_specific,omitempty"`
}

type Credit struct {
	Name string `json:"name"`
}

type DatabaseSpecific struct {
	URL string `json:"url,omitempty"`
}

// Time is a wrapper for time.Time that marshals and unmarshals
// RFC3339 formatted UTC strings.
type Time struct {
	time.Time
}

// MarshalJSON encodes the time as
// an RFC3339-formatted string in UTC (ending in "Z"),
// as required by the OSV specification.
func (t *Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.UTC().Format(time.RFC3339))
}

// UnmarshalJSON decodes an RFC3339-formatted string
// into a Time struct. It errors if data
// is not a valid RFC3339-formatted string.
func (t *Time) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	time, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return err
	}
	t.Time = time.UTC()
	return nil
}
