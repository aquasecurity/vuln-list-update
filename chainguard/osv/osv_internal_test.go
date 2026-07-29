package osv

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	genericosv "github.com/aquasecurity/vuln-list-update/osv"
)

func TestArchFromPURL(t *testing.T) {
	tests := []struct {
		purl string
		want string
	}{
		{"pkg:apk/chainguard/curl?arch=x86_64", "x86_64"},
		{"pkg:apk/chainguard/curl?arch=aarch64", "aarch64"},
		{"pkg:apk/chainguard/curl?distro=20230214&arch=x86_64", "x86_64"},
		{"pkg:apk/chainguard/curl?arch=x86_64&distro=20230214", "x86_64"},
		{"pkg:apk/chainguard/curl?arch=", ""},
		{"pkg:apk/chainguard/curl?distro=20230214", ""},
		{"pkg:apk/chainguard/curl", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			assert.Equal(t, tt.want, archFromPURL(tt.purl))
		})
	}
}

func TestAddRecord_skipsUnusableNames(t *testing.T) {
	tests := []struct {
		name        string
		pkgName     string
		ecosystem   string
		wantSkipped int
		wantStored  bool
	}{
		{
			name:       "usable name",
			pkgName:    "curl",
			ecosystem:  "Chainguard",
			wantStored: true,
		},
		{
			name:        "path traversal",
			pkgName:     "../escape",
			ecosystem:   "Chainguard",
			wantSkipped: 1,
		},
		{
			name:        "absolute path",
			pkgName:     "/etc/passwd",
			ecosystem:   "Chainguard",
			wantSkipped: 1,
		},
		{
			name:        "leading dot",
			pkgName:     ".hidden",
			ecosystem:   "Chainguard",
			wantSkipped: 1,
		},
		{
			name:        "too long for a file name",
			pkgName:     strings.Repeat("a", maxPkgNameLen+1),
			ecosystem:   "Chainguard",
			wantSkipped: 1,
		},
		{
			// Not skipped, just not ours: counting it would misreport the
			// number of unusable names.
			name:      "unsupported ecosystem",
			pkgName:   "curl",
			ecosystem: "Debian",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packages := make(map[packageKey]*Package)
			skipped := addRecord(packages, record{
				ID:       "CGA-2222-2222-2222",
				Upstream: []string{"CVE-2026-11111"},
				Affected: []affected{
					{
						Package: genericosv.Package{
							Ecosystem: tt.ecosystem,
							Name:      tt.pkgName,
							Purl:      "pkg:apk/chainguard/x?arch=x86_64",
						},
						Ranges: []genericosv.Range{
							{
								Type:   "ECOSYSTEM",
								Events: []genericosv.Event{{Introduced: "0"}, {Fixed: "1.0.0-r0"}},
							},
						},
						EcosystemSpecific: ecosystemSpecific{
							Components: []component{{Architecture: "x86_64", LatestEventStatus: "fixed"}},
						},
					},
				},
			})

			assert.Equal(t, tt.wantSkipped, skipped)
			if tt.wantStored {
				require.Len(t, packages, 1)
			} else {
				assert.Empty(t, packages)
			}
		})
	}
}

func TestStatus_precedence(t *testing.T) {
	tests := []struct {
		name       string
		components []component
		want       string
	}{
		{
			name:       "no components",
			components: nil,
			want:       "",
		},
		{
			name:       "single component",
			components: []component{{LatestEventStatus: "fixed"}},
			want:       "fixed",
		},
		{
			name: "unresolved beats resolved",
			components: []component{
				{LatestEventStatus: "fixed"},
				{LatestEventStatus: "detection"},
			},
			want: "detection",
		},
		{
			name: "the most pressing unresolved status wins",
			components: []component{
				{LatestEventStatus: "detection"},
				{LatestEventStatus: "pending_upstream_fix"},
				{LatestEventStatus: "true_positive_determination"},
			},
			want: "true_positive_determination",
		},
		{
			name: "a fix beats a false positive",
			components: []component{
				{LatestEventStatus: "false_positive_determination"},
				{LatestEventStatus: "fixed"},
			},
			want: "fixed",
		},
		{
			name: "an unrecognized status is carried through",
			components: []component{
				{LatestEventStatus: "something_new_from_chainguard"},
			},
			want: "something_new_from_chainguard",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, status(tt.components))
		})
	}
}
