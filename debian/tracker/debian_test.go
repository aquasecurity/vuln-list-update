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

func TestClient_Update1(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    map[string]tracker.Bug
		wantErr string
	}{
		{
			name:  "happy path",
			input: "file::testdata/happy",
			want: map[string]tracker.Bug{
				filepath.Join("DLA", "DLA-2711-1.json"): {
					Header: &tracker.Header{
						Original:    "[19 Jul 2021] DLA-2711-1 thunderbird - security update",
						Line:        1,
						ID:          "DLA-2711-1",
						Description: "thunderbird - security update",
					},
					Annotations: []*tracker.Annotation{
						{
							Original: "{CVE-2021-29969 CVE-2021-29970 CVE-2021-29976 CVE-2021-30547}",
							Line:     2,
							Type:     "xref",
							Bugs:     []string{"CVE-2021-29969", "CVE-2021-29970", "CVE-2021-29976", "CVE-2021-30547"},
						},
						{
							Original: "[stretch] - thunderbird 1:78.12.0-1~deb9u1",
							Line:     3,
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
						Line:        1,
						ID:          "DSA-4480-1",
						Description: "redis - security update",
					},
					Annotations: []*tracker.Annotation{
						{
							Original: "{CVE-2019-10192 CVE-2019-10193}",
							Line:     2,
							Type:     "xref",
							Bugs:     []string{"CVE-2019-10192", "CVE-2019-10193"},
						},
						{
							Original: "[stretch] - redis 3:3.2.6-3+deb9u3",
							Line:     3,
							Type:     "package",
							Release:  "stretch",
							Package:  "redis",
							Kind:     "fixed",
							Version:  "3:3.2.6-3+deb9u3",
						},
						{
							Original: "[buster] - redis 5:5.0.3-4+deb10u1",
							Line:     4,
							Type:     "package",
							Release:  "buster",
							Package:  "redis",
							Kind:     "fixed",
							Version:  "5:5.0.3-4+deb10u1",
						},
					},
				},
				filepath.Join("CVE", "CVE-2021-36373.json"): {
					Header: &tracker.Header{
						Original:    "CVE-2021-36373 (When reading a specially crafted TAR archive an Apache Ant build can b ...)",
						Line:        5,
						ID:          "CVE-2021-36373",
						Description: "(When reading a specially crafted TAR archive an Apache Ant build can b ...)",
					},
					Annotations: []*tracker.Annotation{
						{
							Original: "- ant <unfixed> (unimportant)",
							Line:     6,
							Type:     "package",
							Kind:     "unfixed",
							Package:  "ant",
							Severity: "unimportant",
						},
						{
							Original:    "NOTE: https://www.openwall.com/lists/oss-security/2021/07/13/5",
							Line:        7,
							Type:        "NOTE",
							Description: "https://www.openwall.com/lists/oss-security/2021/07/13/5",
						},
						{
							Original:    "NOTE: Crash in CLI tool, no security impact",
							Line:        8,
							Type:        "NOTE",
							Description: "Crash in CLI tool, no security impact",
						},
					},
				},
				filepath.Join("CVE", "CVE-2021-36367.json"): {
					Header: &tracker.Header{
						Original:    "CVE-2021-36367 (PuTTY through 0.75 proceeds with establishing an SSH session even if i ...)",
						Line:        10,
						ID:          "CVE-2021-36367",
						Description: "(PuTTY through 0.75 proceeds with establishing an SSH session even if i ...)",
					},
					Annotations: []*tracker.Annotation{
						{
							Original: "- putty 0.75-3 (bug #990901)",
							Line:     11,
							Type:     "package",
							Version:  "0.75-3",
							Kind:     "fixed",
							Package:  "putty",
							BugNo:    990901,
						},
						{
							Original:    "[bullseye] - putty <no-dsa> (Minor issue)",
							Line:        12,
							Type:        "package",
							Release:     "bullseye",
							Kind:        "no-dsa",
							Package:     "putty",
							Description: "Minor issue",
						},
						{
							Original:    "[buster] - putty <no-dsa> (Minor issue)",
							Line:        13,
							Type:        "package",
							Release:     "buster",
							Kind:        "no-dsa",
							Package:     "putty",
							Description: "Minor issue",
						},
					},
				},
			},
		},
		{
			name:    "sad path",
			input:   "file::testdata/sad",
			wantErr: "no such file or directory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			c := tracker.NewClient(tracker.WithURL(tt.input), tracker.WithVulnListDir(tmpDir))

			err := c.Update()
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)

			for name, want := range tt.want {
				f, err := os.Open(filepath.Join(tmpDir, "debian", name))
				require.NoError(t, err)

				var got tracker.Bug
				err = json.NewDecoder(f).Decode(&got)
				require.NoError(t, err)

				assert.Equal(t, want, got)
			}
		})
	}
}
