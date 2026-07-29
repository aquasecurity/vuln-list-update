package osv

import genericosv "github.com/aquasecurity/vuln-list-update/osv"

// record is a single advisory record from the Chainguard OSV v3 feed.
//
// The OSV schema parts reuse the shared types in the generic osv package; only
// the two fields Chainguard adds on top of the schema are declared here. The
// generic package's Affected type holds ecosystem_specific as an untyped value,
// so the affected entries are declared locally to get at the components.
// See https://github.com/chainguard-dev/vulnerability-scanner-support/blob/main/docs/osv_v3_feed.md
type record struct {
	ID string `json:"id"`

	// Upstream is Chainguard's name for what OSV calls aliases.
	Upstream []string `json:"upstream"`

	Affected []affected `json:"affected"`
}

type affected struct {
	Package           genericosv.Package `json:"package"`
	Ranges            []genericosv.Range `json:"ranges"`
	EcosystemSpecific ecosystemSpecific  `json:"ecosystem_specific"`
}

type ecosystemSpecific struct {
	Components []component `json:"components"`
}

type component struct {
	Architecture      string `json:"architecture"`
	LatestEventStatus string `json:"latest_event_status"`
}

// Event is an OSV range event.
type Event = genericosv.Event

// Advisory is one Chainguard advisory as it applies to a single package and
// architecture. The v3 feed publishes one advisory per vulnerable component, so
// a package commonly has several advisories for the same vulnerability, which
// are aggregated by the consumer rather than here.
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
//
// The advisory's `modified` timestamp is deliberately not carried through. No
// consumer reads it, the feed is mirrored by full replacement so there are
// never two records with the same ID to choose between, and including it would
// rewrite most of these files on every run.
type Package struct {
	// Ecosystem is the OSV ecosystem, either Chainguard or Wolfi.
	Ecosystem string `json:"ecosystem"`

	// Name is the APK package name, e.g. curl, openssl, go-1.23.
	Name string `json:"name"`

	// Advisories is sorted by advisory ID then architecture so that the
	// generated files are stable across runs.
	Advisories []Advisory `json:"advisories"`
}
