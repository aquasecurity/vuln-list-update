package tracker_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/debian/tracker"
)

type pkgDetail struct {
	Package []string
	Version []string
}

func TestClient_Update(t *testing.T) {
	tests := []struct {
		name                string
		repoPath            string
		sourcesPath         string
		securitySourcesPath string
		wantBugs            map[string]tracker.Bug
		wantDists           map[string]tracker.Distribution
		wantSources         map[string]pkgDetail
		wantErr             string
	}{
		{
			name:                "happy path",
			repoPath:            "file::testdata/happy",
			sourcesPath:         "file::testdata/happy/source/%s/%s/Sources",
			securitySourcesPath: "file::testdata/happy/updates-source/%s/%s/Sources",
			wantBugs: map[string]tracker.Bug{
				filepath.Join("DLA", "DLA-2711-1.json"): {
					Header: &tracker.Header{
						Original:    "[19 Jul 2021] DLA-2711-1 thunderbird - security update",
						ID:          "DLA-2711-1",
						Description: "thunderbird - security update",
					},
					Annotations: []*tracker.Annotation{
						{
							Original: "{CVE-2021-29969 CVE-2021-29970 CVE-2021-29976 CVE-2021-30547}",
							Type:     "xref",
							Bugs: []string{
								"CVE-2021-29969",
								"CVE-2021-29970",
								"CVE-2021-29976",
								"CVE-2021-30547",
							},
						},
						{
							Original: "[stretch] - thunderbird 1:78.12.0-1~deb9u1",
							Type:     "package",
							Release:  "stretch",
							Package:  "thunderbird",
							Kind:     "fixed",
							Version:  "1:78.12.0-1~deb9u1",
						},
					},
				},
				filepath.Join("DSA", "DSA-4480-1.json"): {
					Header: &tracker.Header{
						Original:    "[11 Jul 2019] DSA-4480-1 redis - security update",
						ID:          "DSA-4480-1",
						Description: "redis - security update",
					},
					Annotations: []*tracker.Annotation{
						{
							Original: "{CVE-2019-10192 CVE-2019-10193}",
							Type:     "xref",
							Bugs: []string{
								"CVE-2019-10192",
								"CVE-2019-10193",
							},
						},
						{
							Original: "[stretch] - redis 3:3.2.6-3+deb9u3",
							Type:     "package",
							Release:  "stretch",
							Package:  "redis",
							Kind:     "fixed",
							Version:  "3:3.2.6-3+deb9u3",
						},
						{
							Original: "[buster] - redis 5:5.0.3-4+deb10u1",
							Type:     "package",
							Release:  "buster",
							Package:  "redis",
							Kind:     "fixed",
							Version:  "5:5.0.3-4+deb10u1",
						},
					},
				},
				filepath.Join("CVE", "2021", "CVE-2021-36373.json"): {
					Header: &tracker.Header{
						Original:    "CVE-2021-36373 (When reading a specially crafted TAR archive an Apache Ant build can b ...)",
						ID:          "CVE-2021-36373",
						Description: "(When reading a specially crafted TAR archive an Apache Ant build can b ...)",
					},
					Annotations: []*tracker.Annotation{
						{
							Original: "- ant <unfixed> (unimportant)",
							Type:     "package",
							Kind:     "unfixed",
							Package:  "ant",
							Severity: "unimportant",
						},
						{
							Original:    "NOTE: https://www.openwall.com/lists/oss-security/2021/07/13/5",
							Type:        "NOTE",
							Description: "https://www.openwall.com/lists/oss-security/2021/07/13/5",
						},
						{
							Original:    "NOTE: Crash in CLI tool, no security impact",
							Type:        "NOTE",
							Description: "Crash in CLI tool, no security impact",
						},
					},
				},
				filepath.Join("CVE", "2021", "CVE-2021-36367.json"): {
					Header: &tracker.Header{
						Original:    "CVE-2021-36367 (PuTTY through 0.75 proceeds with establishing an SSH session even if i ...)",
						ID:          "CVE-2021-36367",
						Description: "(PuTTY through 0.75 proceeds with establishing an SSH session even if i ...)",
					},
					Annotations: []*tracker.Annotation{
						{
							Original: "- putty 0.75-3 (low; bug #990901)",
							Type:     "package",
							Version:  "0.75-3",
							Kind:     "fixed",
							Package:  "putty",
							Severity: "low",
							BugNo:    990901,
						},
						{
							Original:    "[bullseye] - putty <no-dsa> (Minor issue)",
							Type:        "package",
							Release:     "bullseye",
							Kind:        "no-dsa",
							Package:     "putty",
							Description: "Minor issue",
						},
						{
							Original:    "[buster] - putty <no-dsa> (Minor issue)",
							Type:        "package",
							Release:     "buster",
							Kind:        "no-dsa",
							Package:     "putty",
							Description: "Minor issue",
						},
					},
				},
				filepath.Join("CVE", "TEMP", "TEMP-1053115-9454E3.json"): {
					Header: &tracker.Header{
						Original:    "CVE-2023-XXXX [code execution via malformed XTGETTCAP]",
						ID:          "TEMP-1053115-9454E3",
						Description: "[code execution via malformed XTGETTCAP]",
					},
					Annotations: []*tracker.Annotation{
						{
							Original: "- foot 1.15.3-2 (bug #1053115)",
							Type:     "package",
							Package:  "foot",
							Kind:     "fixed",
							Version:  "1.15.3-2",
							BugNo:    1053115,
						},
						{
							Original: "[bookworm] - foot 1.13.1-2+deb12u1",
							Type:     "package",
							Release:  "bookworm",
							Package:  "foot",
							Kind:     "fixed",
							Version:  "1.13.1-2+deb12u1",
						},
						{
							Original:    "[bullseye] - foot <no-dsa> (Minor issue)",
							Type:        "package",
							Release:     "bullseye",
							Package:     "foot",
							Kind:        "no-dsa",
							Description: "Minor issue",
						},
						{
							Original:    "NOTE: https://codeberg.org/dnkl/foot/commit/8a5f2915e9d327d1517d1da49ce7e2303fe61d36",
							Type:        "NOTE",
							Description: "https://codeberg.org/dnkl/foot/commit/8a5f2915e9d327d1517d1da49ce7e2303fe61d36",
						},
					},
				},
				filepath.Join("CVE", "TEMP", "TEMP-0000000-556898.json"): {
					Header: &tracker.Header{
						Original:    "CVE-2023-XXXX [Other security issues from wordpress 6.3.2]",
						ID:          "TEMP-0000000-556898",
						Description: "[Other security issues from wordpress 6.3.2]",
					},
					Annotations: []*tracker.Annotation{
						{
							Original: "- wordpress <unfixed>",
							Type:     "package",
							Package:  "wordpress",
							Kind:     "unfixed",
						},
						{
							Original:    "NOTE: https://wordpress.org/documentation/wordpress-version/version-6-3-2/",
							Type:        "NOTE",
							Description: "https://wordpress.org/documentation/wordpress-version/version-6-3-2/",
						},
					},
				},
			},
			wantDists: map[string]tracker.Distribution{
				"stretch": {
					MajorVersion: "9",
					Support:      "lts",
					Contact:      "debian-lts@lists.debian.org",
				},
				"buster": {
					MajorVersion: "10",
					Support:      "security",
					Contact:      "team@security.debian.org",
				},
			},
			wantSources: map[string]pkgDetail{
				filepath.Join("source", "stretch", "main", "0", "0ad.json"): {
					Package: []string{"0ad"},
					Version: []string{"0.0.21-2"},
				},
				filepath.Join("source", "stretch", "main", "0", "0ad-data.json"): {
					Package: []string{"0ad-data"},
					Version: []string{"0.0.21-1"},
				},
				filepath.Join("updates-source", "stretch", "main", "0", "0ad.json"): {
					Package: []string{"0ad"},
					Version: []string{"0.0.21-2"},
				},
				filepath.Join("updates-source", "stretch", "main", "0", "0ad-data.json"): {
					Package: []string{"0ad-data"},
					Version: []string{"0.0.21-1"},
				},
				filepath.Join("source", "stretch", "contrib", "a", "alien-arena.json"): {
					Package: []string{"alien-arena"},
					Version: []string{"7.66+dfsg-3"},
				},
				filepath.Join("updates-source", "stretch", "contrib", "a", "alien-arena.json"): {
					Package: []string{"alien-arena"},
					Version: []string{"7.66+dfsg-3"},
				},
				filepath.Join("source", "buster", "main", "z", "zzz-to-char.json"): {
					Package: []string{"zzz-to-char"},
					Version: []string{"0.1.3-2"},
				},
				filepath.Join("source", "buster", "main", "z", "zzzeeksphinx.json"): {
					Package: []string{"zzzeeksphinx"},
					Version: []string{"1.0.20-2"},
				},
				filepath.Join("updates-source", "buster", "main", "z", "zzz-to-char.json"): {
					Package: []string{"zzz-to-char"},
					Version: []string{"0.1.3-3"},
				},
				filepath.Join("source", "buster", "contrib", "z", "zfs-auto-snapshot.json"): {
					Package: []string{"zfs-auto-snapshot"},
					Version: []string{"1.2.4-2"},
				},
				filepath.Join("source", "buster", "contrib", "z", "zfs-linux.json"): {
					Package: []string{"zfs-linux"},
					Version: []string{"0.7.12-2+deb10u2"},
				},
				filepath.Join("updates-source", "buster", "contrib", "z", "zfs-linux.json"): {
					Package: []string{"zfs-linux"},
					Version: []string{"0.7.12-2+deb10u3"},
				},
			},
		},
		{
			name:     "sad path",
			repoPath: "file::testdata/sad",
			wantErr:  "no such file or directory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			c := tracker.NewClient(tracker.WithTrackerURL(tt.repoPath), tracker.WithSourcesURL(tt.sourcesPath),
				tracker.WithSecuritySourcesURL(tt.securitySourcesPath), tracker.WithVulnListDir(tmpDir))

			err := c.Update()
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)

			// Compare CVE/list, DLA/list, and DSA/list
			for name, want := range tt.wantBugs {
				var got tracker.Bug
				filePath := filepath.Join(tmpDir, "tracker", name)
				compare(t, filePath, &got, &want)
			}

			// Compare distributions.json
			{
				var got map[string]tracker.Distribution
				filePath := filepath.Join(tmpDir, "tracker", "distributions.json")
				compare(t, filePath, &got, &tt.wantDists)
			}

			// Compare Sources
			for name, want := range tt.wantSources {
				var got pkgDetail
				filePath := filepath.Join(tmpDir, "tracker", name)
				compare(t, filePath, &got, &want)
			}
		})
	}
}

func compare(t *testing.T, gotPath string, got, want interface{}) {
	t.Helper()

	f, err := os.Open(gotPath)
	require.NoError(t, err)

	err = json.NewDecoder(f).Decode(got)
	require.NoError(t, err)

	assert.Equal(t, want, got)
}
