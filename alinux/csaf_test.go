package alinux

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parseNEVRA(t *testing.T) {
	tests := []struct {
		name        string
		nevra       string
		wantName    string
		wantEpoch   string
		wantVersion string
		wantRelease string
		wantArch    string
		wantErr     bool
	}{
		{
			name:        "simple package",
			nevra:       "curl-7.61.1-22.al8.3.x86_64",
			wantName:    "curl",
			wantEpoch:   "0",
			wantVersion: "7.61.1",
			wantRelease: "22.al8.3",
			wantArch:    "x86_64",
		},
		{
			name:        "package with epoch",
			nevra:       "openssl-1:1.0.2k-25.al2.x86_64",
			wantName:    "openssl",
			wantEpoch:   "1",
			wantVersion: "1.0.2k",
			wantRelease: "25.al2",
			wantArch:    "x86_64",
		},
		{
			name:        "multi-dash package name",
			nevra:       "kernel-headers-5.10.134-16.3.al8.x86_64",
			wantName:    "kernel-headers",
			wantEpoch:   "0",
			wantVersion: "5.10.134",
			wantRelease: "16.3.al8",
			wantArch:    "x86_64",
		},
		{
			name:        "source package",
			nevra:       "curl-7.61.1-22.al8.3.src",
			wantName:    "curl",
			wantEpoch:   "0",
			wantVersion: "7.61.1",
			wantRelease: "22.al8.3",
			wantArch:    "src",
		},
		{
			name:        "noarch package",
			nevra:       "tzdata-2023c-1.al8.noarch",
			wantName:    "tzdata",
			wantEpoch:   "0",
			wantVersion: "2023c",
			wantRelease: "1.al8",
			wantArch:    "noarch",
		},
		{
			name:    "no arch separator",
			nevra:   "invalid-package",
			wantErr: true,
		},
		{
			name:    "no release separator",
			nevra:   "invalid.x86_64",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, epoch, ver, rel, arch, err := parseNEVRA(tt.nevra)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantName, name)
			assert.Equal(t, tt.wantEpoch, epoch)
			assert.Equal(t, tt.wantVersion, ver)
			assert.Equal(t, tt.wantRelease, rel)
			assert.Equal(t, tt.wantArch, arch)
		})
	}
}

func Test_deduplicatePackages(t *testing.T) {
	tests := []struct {
		name string
		pkgs []Package
		want []Package
	}{
		{
			name: "with duplicates",
			pkgs: []Package{
				{Name: "curl", Epoch: "0", Version: "7.61.1", Release: "22.al8.3"},
				{Name: "curl", Epoch: "0", Version: "7.61.1", Release: "22.al8.3"},
				{Name: "libcurl", Epoch: "0", Version: "7.61.1", Release: "22.al8.3"},
			},
			want: []Package{
				{Name: "curl", Epoch: "0", Version: "7.61.1", Release: "22.al8.3"},
				{Name: "libcurl", Epoch: "0", Version: "7.61.1", Release: "22.al8.3"},
			},
		},
		{
			name: "no duplicates",
			pkgs: []Package{
				{Name: "curl", Epoch: "0", Version: "7.61.1", Release: "22.al8.3"},
				{Name: "libcurl", Epoch: "0", Version: "7.61.1", Release: "22.al8.3"},
			},
			want: []Package{
				{Name: "curl", Epoch: "0", Version: "7.61.1", Release: "22.al8.3"},
				{Name: "libcurl", Epoch: "0", Version: "7.61.1", Release: "22.al8.3"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deduplicatePackages(tt.pkgs)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_convertCSAFToALSA(t *testing.T) {
	tests := []struct {
		name    string
		doc     CSAFDocument
		want    []ALSA
		wantNil bool
	}{
		{
			name: "single CVE",
			doc: CSAFDocument{
				Document: CSAFDocumentMeta{
					Title: "Test Advisory",
					Tracking: CSAFTracking{
						ID:                 "ALINUX3-SA-2024:0001",
						InitialReleaseDate: "2024-01-15",
						CurrentReleaseDate: "2024-01-15",
					},
					AggregateSeverity: CSAFAggregateSeverity{Text: "Important"},
					Notes: []CSAFNote{
						{Category: "description", Text: "Advisory description"},
					},
				},
				ProductTree: CSAFProductTree{
					Relationships: []CSAFRelationship{
						{
							ProductReference:          "curl-7.61.1-22.al8.3.x86_64",
							RelatesToProductReference: "Alinux 3",
							FullProductName:           CSAFFullProductName{ProductID: "Alinux 3:curl-7.61.1-22.al8.3.x86_64"},
						},
					},
				},
				Vulnerabilities: []CSAFVulnerability{
					{
						CVE: "CVE-2024-0001",
						ProductStatus: CSAFProductStatus{
							Fixed: []string{"Alinux 3:curl-7.61.1-22.al8.3.x86_64"},
						},
						Scores: []CSAFScore{
							{CvssV3: CSAFCvssV3{VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", BaseScore: 7.5}},
						},
						Threats: []CSAFThreat{{Category: "impact", Details: "Important"}},
					},
				},
			},
			want: []ALSA{
				{
					ID:          "ALINUX3-SA-2024:0001",
					Title:       "Test Advisory",
					Severity:    "Important",
					Description: "Advisory description",
					Issued:      DateJSON{Date: "2024-01-15"},
					Updated:     DateJSON{Date: "2024-01-15"},
					CveIDs:      []string{"CVE-2024-0001"},
					Packages: []Package{
						{Name: "curl", Epoch: "0", Version: "7.61.1", Release: "22.al8.3"},
					},
					References: []CveRef{
						{ID: "CVE-2024-0001", Href: "https://alas.aliyuncs.com/cves/detail/CVE-2024-0001", Cvss3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", Impact: "Important"},
					},
				},
			},
		},
		{
			name: "empty vulnerabilities",
			doc: CSAFDocument{
				Document: CSAFDocumentMeta{
					Title: "Empty Advisory",
					Tracking: CSAFTracking{
						ID: "ALINUX3-SA-2024:0002",
					},
				},
			},
			wantNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertCSAFToALSA(tt.doc)
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, got)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_extractPackagesFromFixed(t *testing.T) {
	relMap := map[string]CSAFRelationship{
		"Alinux 3:curl-7.61.1-22.al8.3.x86_64": {
			ProductReference:          "curl-7.61.1-22.al8.3.x86_64",
			RelatesToProductReference: "Alinux 3",
		},
		"Alinux 3:curl-7.61.1-22.al8.3.src": {
			ProductReference:          "curl-7.61.1-22.al8.3.src",
			RelatesToProductReference: "Alinux 3",
		},
		"Alinux 3:curl-debuginfo-7.61.1-22.al8.3.x86_64": {
			ProductReference:          "curl-debuginfo-7.61.1-22.al8.3.x86_64",
			RelatesToProductReference: "Alinux 3",
		},
		"Alinux 3:libcurl-7.61.1-22.al8.3.x86_64": {
			ProductReference:          "libcurl-7.61.1-22.al8.3.x86_64",
			RelatesToProductReference: "Alinux 3",
		},
	}

	tests := []struct {
		name     string
		fixedIDs []string
		want     []Package
	}{
		{
			name: "extract packages, skip src and debuginfo",
			fixedIDs: []string{
				"Alinux 3:curl-7.61.1-22.al8.3.x86_64",
				"Alinux 3:curl-7.61.1-22.al8.3.src",
				"Alinux 3:curl-debuginfo-7.61.1-22.al8.3.x86_64",
				"Alinux 3:libcurl-7.61.1-22.al8.3.x86_64",
			},
			want: []Package{
				{Name: "curl", Epoch: "0", Version: "7.61.1", Release: "22.al8.3"},
				{Name: "libcurl", Epoch: "0", Version: "7.61.1", Release: "22.al8.3"},
			},
		},
		{
			name:     "empty fixed IDs",
			fixedIDs: []string{},
			want:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPackagesFromFixed(tt.fixedIDs, relMap)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_fetchFileList(t *testing.T) {
	tests := []struct {
		name    string
		html    string
		pattern string
		want    []string
	}{
		{
			name: "advisory files",
			html: `<html><body>
<a href="alinux2-sa-2023_0001.json">alinux2-sa-2023_0001.json</a>
<a href="alinux3-sa-2024_0001.json">alinux3-sa-2024_0001.json</a>
<a href="other.txt">other.txt</a>
</body></html>`,
			pattern: "advisory",
			want:    []string{"alinux2-sa-2023_0001.json", "alinux3-sa-2024_0001.json"},
		},
		{
			name: "VEX files",
			html: `<html><body>
<a href="CVE-2023-12345.json">CVE-2023-12345.json</a>
<a href="CVE-2024-0001.json">CVE-2024-0001.json</a>
<a href="README.md">README.md</a>
</body></html>`,
			pattern: "vex",
			want:    []string{"CVE-2023-12345.json", "CVE-2024-0001.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, tt.html)
			}))
			defer ts.Close()

			var re = advisoryFileRe
			if tt.pattern == "vex" {
				re = vexFileRe
			}
			got, err := fetchFileList(ts.URL, re)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
