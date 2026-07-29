package osv

// record is a single advisory record from the Chainguard OSV v3 feed.
// Only the fields consumed downstream are declared; see
// https://github.com/chainguard-dev/vulnerability-scanner-support/blob/main/docs/osv_v3_feed.md
type record struct {
	ID       string     `json:"id"`
	Upstream []string   `json:"upstream"`
	Affected []affected `json:"affected"`
}

type affected struct {
	Package           pkg               `json:"package"`
	Ranges            []versionRange    `json:"ranges"`
	EcosystemSpecific ecosystemSpecific `json:"ecosystem_specific"`
}

type pkg struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl"`
}

type versionRange struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type ecosystemSpecific struct {
	Components []component `json:"components"`
}

type component struct {
	Architecture      string `json:"architecture"`
	LatestEventStatus string `json:"latest_event_status"`
}

// Event is an OSV range event. Exactly one of the fields is set.
type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// Advisory is one Chainguard advisory as it applies to a single package and
// architecture. The Chainguard v3 feed publishes one advisory per record, so a
// package usually has many advisories per vulnerability - one for each
// vulnerable component found inside the package. Consumers are expected to
// aggregate them; this file keeps them separate so no information is lost.
type Advisory struct {
	// ID is the Chainguard advisory ID, e.g. CGA-2637-w437-j654.
	ID string `json:"id"`

	// Upstream lists the upstream vulnerability IDs this advisory describes,
	// e.g. CVE-2023-38545, GHSA-7xw9-w465-6x42, GO-1234-1234.
	Upstream []string `json:"upstream,omitempty"`

	// Arch is the CPU architecture of the package build, taken from the
	// ?arch= qualifier of the affected package PURL, e.g. x86_64, aarch64.
	// Empty when the feed does not qualify the package by architecture.
	Arch string `json:"arch,omitempty"`

	// Events holds the OSV ECOSYSTEM range events verbatim. An "introduced"
	// event with no "fixed" event means the advisory is unresolved and every
	// version is affected. A "fixed" version of "0" marks a false positive.
	Events []Event `json:"events"`

	// Status is the resolution status of the advisory, e.g. fixed,
	// false_positive_determination, pending_upstream_fix.
	Status string `json:"status,omitempty"`
}

// Package holds every advisory published for one package within one ecosystem.
type Package struct {
	// Ecosystem is the OSV ecosystem, either Chainguard or Wolfi.
	Ecosystem string `json:"ecosystem"`

	// Name is the APK package name, e.g. curl, openssl, go-1.23.
	Name string `json:"name"`

	// Advisories is sorted by advisory ID then architecture so that the
	// generated files are stable across runs.
	Advisories []Advisory `json:"advisories"`
}
