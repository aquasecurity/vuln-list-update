package echo

type Advisory map[string]map[string]struct {
	Severity     string `json:"severity,omitempty"`
	FixedVersion string `json:"fixed_version,omitempty"`
}
