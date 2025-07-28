package ubuntu

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parse(t *testing.T) {
	type args struct {
		filePath string
	}
	testCases := []struct {
		name    string
		args    args
		want    *Vulnerability
		wantErr error
	}{
		{
			name: "when empty upstream patch is passed",
			args: args{
				filePath: "./testdata/empty_status_upstream",
			},
			want: &Vulnerability{
				Candidate:   "CVE-2007-0255",
				References:  []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0255"},
				Description: "XINE 0.99.4 allows user-assisted remote attackers to cause a denial of service (application crash) and possibly execute arbitrary code via a certain M3U file that contains a long #EXTINF line and contains format string specifiers in an invalid udp:// URI, possibly a variant of CVE-2007-0017.",
				PublicDate:  time.Date(2007, 1, 16, 23, 28, 0, 0, time.UTC),
				Patches: map[Package]Statuses{
					Package("xine-ui"): {
						"dapper": Status{
							Status: "ignored",
							Note:   "reached end-of-life",
						},
						"edgy": Status{
							Status: "needed",
							Note:   "reached end-of-life",
						},
						"vivid/stable-phone-overlay": Status{
							Status: "DNE",
						},
						"vivid/ubuntu-core": Status{
							Status: "DNE",
						},
						"wily": Status{
							Status: "ignored",
							Note:   "reached end-of-life",
						},
						"xenial": Status{
							Status: "needed",
						},
					},
				},
				UpstreamLinks: map[Package][]string{},
			},
		},
		{
			name: "when line break is present between patch",
			args: args{
				filePath: "./testdata/line_break_between_patches",
			},
			want: &Vulnerability{
				Candidate: "CVE-2017-7702",
				References: []string{
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7702",
					"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=13477",
					"https://code.wireshark.org/review/gitweb?p=wireshark.git;a=commit;h=2f322f66cbcca2fefdaa630494f9d6c97eb659b7",
					"https://www.wireshark.org/security/wnpa-sec-2017-13.html",
				},
				Description:  "In Wireshark 2.2.0 to 2.2.5 and 2.0.0 to 2.0.11, the WBXML dissector could go into an infinite loop, triggered by packet injection or a malformed capture file. This was addressed in epan/dissectors/packet-wbxml.c by adding length validation.",
				Priority:     "medium",
				DiscoveredBy: "Otto Airamo and Antti Levomäki",
				PublicDate:   time.Date(2007, 1, 16, 23, 28, 0, 0, time.UTC),
				Patches: map[Package]Statuses{
					Package("wireshark"): {
						"upstream": Status{
							Status: "released",
							Note:   "2.2.6, 2.0.12",
						},
						"precise": Status{
							Status: "ignored",
							Note:   "reached end-of-life",
						},
						"precise/esm": Status{
							Status: "DNE",
							Note:   "precise was needed",
						},
						"trusty/esm": Status{
							Status: "released",
							Note:   "2.6.3-1~ubuntu14.04.1",
						},
						"vivid/stable-phone-overlay": Status{
							Status: "DNE",
						},
						"xenial": Status{
							Status: "released",
							Note:   "2.6.3-1~ubuntu16.04.1",
						},
						"yakkety": Status{
							Status: "released",
							Note:   "2.2.6+g32dac6a-2ubuntu0.16.10",
						},
						"bionic": Status{
							Status: "released",
							Note:   "2.6.3-1~ubuntu18.04.1",
						},
						"devel": Status{
							Status: "not-affected",
							Note:   "2.6.3-1",
						},
					},
				},
				UpstreamLinks: map[Package][]string{},
			},
		},
		{
			name: "more than one package patches",
			args: args{
				filePath: "./testdata/more_than_one_package_patches",
			},
			want: &Vulnerability{
				Candidate: "CVE-2017-9228",
				References: []string{
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9228",
					"https://usn.ubuntu.com/usn/usn-3382-1",
					"https://usn.ubuntu.com/usn/usn-3382-2",
				},
				Description:       "An issue was discovered in Oniguruma 6.2.0, as used in Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP through 7.1.5. A heap out-of-bounds write occurs in bitset_set_range() during regular expression compilation due to an uninitialized variable from an incorrect state transition. An incorrect state transition in parse_char_class() could create an execution path that leaves a critical local variable uninitialized until it's used as an index, resulting in an out-of-bounds write memory corruption.",
				UbuntuDescription: "It was discovered that Oniguruma incorrectly handled certain regular expressions. An attacker could possibly use this issue to obtain sensitive information, cause a denial of service or execute arbitrary code.",
				Priority:          "medium",
				Bugs: []string{
					"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=863316",
					"https://github.com/kkos/oniguruma/issues/60"},
				PublicDate: time.Date(2007, 1, 16, 23, 28, 0, 0, time.UTC),
				Patches: map[Package]Statuses{
					Package("libonig"): {
						"upstream": Status{
							Status: "needs-triage",
						},
						"precise/esm": Status{
							Status: "DNE",
						},
						"artful": Status{
							Status: "ignored",
							Note:   "reached end-of-life",
						},
						"bionic": Status{
							Status: "released",
							Note:   "6.3.0-1",
						},
					},
					Package("php5"): {
						"upstream": Status{
							Status: "needs-triage",
						},
						"precise/esm": Status{
							Status: "released",
							Note:   "5.3.10-1ubuntu3.28",
						},
						"devel": Status{
							Status: "DNE",
						},
					},
					Package("php7.0"): {
						"upstream": Status{
							Status: "needs-triage",
						},
						"precise/esm": Status{
							Status: "DNE",
						},
						"zesty": Status{
							Status: "released",
							Note:   "7.0.22-0ubuntu0.17.04.1",
						},
						"artful": Status{
							Status: "DNE",
						},
					},
				},
				UpstreamLinks: map[Package][]string{
					"libonig": {"https://github.com/kkos/oniguruma/commit/3b63d12038c8d8fc278e81c942fa9bec7c704c8b"},
					"php5":    {"https://github.com/php/php-src/commit/703be4f77e662837b64499b0d046a5c8d06a98b9"},
					"php7.0":  {"https://github.com/php/php-src/commit/1c845d295037702d63097e2216b3c5db53f79273"},
				},
			},
		},
		{
			name: "no space before status",
			args: args{
				filePath: "./testdata/no_space_before_status",
			},
			want: &Vulnerability{
				Candidate: "CVE-2019-15903",
				References: []string{
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-15903",
					"https://github.com/libexpat/libexpat/commit/c20b758c332d9a13afbbb276d30db1d183a85d43",
					"https://github.com/libexpat/libexpat/issues/317",
					"https://github.com/libexpat/libexpat/pull/318",
					"https://usn.ubuntu.com/usn/usn-4132-1",
					"https://usn.ubuntu.com/usn/usn-4132-2",
					"https://www.mozilla.org/en-US/security/advisories/mfsa2019-34/#CVE-2019-15903",
					"https://usn.ubuntu.com/usn/usn-4165-1",
					"https://usn.ubuntu.com/usn/usn-4202-1",
					"https://usn.ubuntu.com/usn/usn-4335-1",
				},
				Description:       "In libexpat before 2.2.8, crafted XML input could fool the parser into changing from DTD parsing to document parsing too early; a consecutive call to XML_GetCurrentLineNumber (or XML_GetCurrentColumnNumber) then resulted in a heap-based buffer over-read.",
				UbuntuDescription: "A heap overflow was discovered in the expat library in XXX-PACKAGE-NAME-HERE-XXX. If a user were tricked into opening a specially crafted XML file, an attacker could potentially exploit this to cause a denial of service or execute arbitrary code.",
				Priority:          "medium",
				Bugs: []string{
					"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=939394",
				},
				PublicDateAtUSN: time.Date(2019, 9, 4, 0, 0, 0, 0, time.UTC),
				PublicDate:      time.Date(2019, 9, 4, 6, 15, 0, 0, time.UTC),
				Patches: map[Package]Statuses{
					Package("vnc4"): {
						"upstream": Status{
							Status: "needs-triage",
						},
						"precise/esm": Status{
							Status: "DNE",
						},
						"trusty": Status{
							Status: "ignored",
							Note:   "out of standard support",
						},
						"trusty/esm": Status{
							Status: "needed",
						},
						"xenial": Status{
							Status: "needed",
						},
						"bionic": Status{
							Status: "needed",
						},
						"disco": Status{
							Status: "not-affected",
							Note:   "code not present",
						},
						"eoan": Status{
							Status: "not-affected",
							Note:   "code not present",
						},
						"focal": Status{
							Status: "DNE",
						},
						"devel": Status{
							Status: "DNE",
						},
					},
				},
				UpstreamLinks: map[Package][]string{},
			},
		},
		{
			name: "Patches with status",
			args: args{
				filePath: "./testdata/patches_with_status",
			},
			want: &Vulnerability{
				Candidate: "CVE-2020-9925",
				References: []string{
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9925",
					"https://webkitgtk.org/security/WSA-2020-0007.html",
					"https://usn.ubuntu.com/usn/usn-4444-1",
				},
				Description:     "A logic issue was addressed with improved state management. Processing maliciously crafted web content may lead to universal cross site scripting.",
				Priority:        "medium",
				PublicDateAtUSN: time.Date(2020, 7, 29, 0, 0, 0, 0, time.UTC),
				PublicDate:      time.Date(2020, 7, 29, 0, 0, 0, 0, time.UTC),
				Notes: []string{
					"jdstrand> webkit receives limited support. For details, see",
					"https://wiki.ubuntu.com/SecurityTeam/FAQ#webkit",
					"jdstrand> webkit in Ubuntu uses the JavaScriptCore (JSC) engine, not V8",
				},
				Patches: map[Package]Statuses{
					Package("qtwebkit-opensource-src"): {
						"upstream": Status{
							Status: "needs-triage",
						},
						"precise/esm": Status{
							Status: "DNE",
						},
						"trusty": Status{
							Status: "ignored",
							Note:   "out of standard support",
						},
						"trusty/esm": Status{
							Status: "DNE",
						},
						"xenial": Status{
							Status: "needs-triage",
						},
						"bionic": Status{
							Status: "needs-triage",
						},
						"focal": Status{
							Status: "needs-triage",
						},
						"devel": Status{
							Status: "needs-triage",
						},
					},
				},
				UpstreamLinks: map[Package][]string{},
			},
		},
		{
			name: "include pending",
			args: args{
				filePath: "./testdata/include_pending",
			},
			want: &Vulnerability{
				Candidate: "CVE-2020-0009",
				References: []string{
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0009",
				},
				Description: "test",
				Priority:    "low",
				PublicDate:  time.Date(2020, 1, 8, 16, 15, 0, 0, time.UTC),
				Notes: []string{
					"cascardo> possible fix is 6d67b0290b4b84c477e6a2fc6e005e174d3c7786",
				},
				Patches: map[Package]Statuses{
					Package("linux-oem"): {
						"upstream": Status{
							Status: "released",
							Note:   "5.6~rc3",
						},
						"precise/esm": Status{
							Status: "DNE",
						},
						"trusty": Status{
							Status: "DNE",
						},
						"trusty/esm": Status{
							Status: "DNE",
						},
						"xenial": Status{
							Status: "ignored",
							Note:   "was needs-triage now end-of-life",
						},
						"bionic": Status{
							Status: "released",
							Note:   "4.15.0-1080.90",
						},
						"eoan": Status{
							Status: "pending",
							Note:   "4.15.0-1087.97",
						},
						"focal": Status{
							Status: "DNE",
						},
						"devel": Status{
							Status: "DNE",
						},
					},
				},
				UpstreamLinks: map[Package][]string{},
			},
		},
		{
			name: "multiple upstreams",
			args: args{
				filePath: "./testdata/multiple_upstreams",
			},
			want: &Vulnerability{
				Candidate: "CVE-2020-0556",
				References: []string{
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0556",
					"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00352.html",
					"https://www.openwall.com/lists/oss-security/2020/03/12/4",
					"https://usn.ubuntu.com/usn/usn-4311-1",
				},
				Description:     "dummy",
				Priority:        "medium",
				PublicDateAtUSN: time.Date(2020, 3, 12, 21, 15, 0, 0, time.UTC),
				PublicDate:      time.Date(2020, 3, 12, 21, 15, 0, 0, time.UTC),
				Bugs: []string{
					"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=953770",
				},
				AssignedTo: "mdeslaur",
				Patches: map[Package]Statuses{
					Package("bluez"): {
						"upstream": Status{
							Status: "released",
							Note:   "5.54",
						},
						"precise/esm": Status{
							Status: "DNE",
						},
						"trusty": Status{
							Status: "ignored",
							Note:   "out of standard support",
						},
						"trusty/esm": Status{
							Status: "DNE",
						},
						"xenial": Status{
							Status: "released",
							Note:   "5.37-0ubuntu5.3",
						},
						"bionic": Status{
							Status: "released",
							Note:   "5.48-0ubuntu3.4",
						},
						"eoan": Status{
							Status: "released",
							Note:   "5.50-0ubuntu5.1",
						},
						"devel": Status{
							Status: "released",
							Note:   "5.53-0ubuntu2",
						},
					},
				},
				UpstreamLinks: map[Package][]string{
					Package("bluez"): {
						"https://git.kernel.org/pub/scm/bluetooth/bluez.git/commit/?id=8cdbd3b09f29da29374e2f83369df24228da0ad1",
						"https://git.kernel.org/pub/scm/bluetooth/bluez.git/commit/?id=3cccdbab2324086588df4ccf5f892fb3ce1f1787",
						"https://git.kernel.org/pub/scm/bluetooth/bluez.git/commit/?id=35d8d895cd0b724e58129374beb0bb4a2edf9519",
						"https://git.kernel.org/pub/scm/bluetooth/bluez.git/commit/?id=f2778f5877d20696d68a452b26e4accb91bfb19e",
					},
				},
			},
		},
		{
			name: "tags field parsing",
			args: args{
				filePath: "./testdata/tags_field_parsing",
			},
			want: &Vulnerability{
				Candidate: "CVE-2022-22965",
				References: []string{
					"https://example.com/reference1",
					"https://example.com/reference2",
				},
				Description:     "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution via data binding.",
				Priority:        "high",
				Tags:            []string{"cisa-kev", "epss-prioritized"},
				PublicDateAtUSN: time.Date(2022, 4, 1, 23, 15, 0, 0, time.UTC),
				PublicDate:      time.Date(2022, 4, 1, 23, 15, 0, 0, time.UTC),
				Patches: map[Package]Statuses{
					Package("libspring-java"): {
						"upstream": Status{
							Status: "released",
							Note:   "5.3.18, 5.2.20",
						},
						"jammy": Status{
							Status: "needed",
						},
						"noble": Status{
							Status: "needed",
						},
					},
				},
				UpstreamLinks: map[Package][]string{},
			},
		},
		{
			name: "blank lines in description",
			args: args{
				filePath: "./testdata/blank_lines_in_description",
			},
			want: &Vulnerability{
				Candidate: "CVE-2017-5192",
				References: []string{
					"https://docs.saltstack.com/en/2016.3/topics/releases/2015.8.13.html",
					"https://www.cve.org/CVERecord?id=CVE-2017-5192",
				},
				Description: "When using the local_batch client from salt-api in SaltStack Salt before 2015.8.13, 2016.3.x before 2016.3.5, and 2016.11.x before 2016.11.2, external authentication is not respected, enabling all authentication to be bypassed. The LocalClient.cmd_batch() method client does not accept external_auth credentials and so access to it from salt-api has been removed for now. This vulnerability allows code execution for already-authenticated users and is only in effect when running salt-api as the root user.",
				Priority:    "medium",
				PublicDate:  time.Date(2017, 9, 26, 14, 29, 0, 0, time.UTC),
				Patches: map[Package]Statuses{
					Package("salt"): {
						"upstream": Status{
							Status: "released",
							Note:   "2016.11.2+ds-1",
						},
						"precise": Status{
							Status: "DNE",
						},
						"trusty": Status{
							Status: "ignored",
							Note:   "end of standard support",
						},
					},
				},
				UpstreamLinks: map[Package][]string{},
			},
		},
		{
			name: "notes with continuation lines",
			args: args{
				filePath: "./testdata/notes_with_continuation_lines",
			},
			want: &Vulnerability{
				Candidate: "CVE-2017-0537",
				References: []string{
					"https://source.android.com/security/bulletin/2017-01-01.html",
					"https://android.googlesource.com/kernel/tegra.git/+/389b185cb2f17fff994dbdf8d4bac003d4b2b6b3%5E%21/#F0",
					"https://lore.kernel.org/lkml/1484647168-30135-1-git-send-email-jilin@nvidia.com/#t",
					"https://www.cve.org/CVERecord?id=CVE-2017-0537",
				},
				Description: "An information disclosure vulnerability in the kernel USB gadget driver could enable a local malicious application to access data outside of its permission levels. This issue is rated as Moderate because it first requires compromising a privileged process. Product: Android. Versions: Kernel-3.18. Android ID: A-31614969.",
				Priority:    "medium",
				PublicDate:  time.Date(2017, 3, 8, 1, 59, 0, 0, time.UTC),
				Notes: []string{
					"sbeattie> see android patch above",
					"sbeattie> drivers/usb/gadget/configfs.c::usb_string_copy()",
					"tyhicks> Patch submitter never verified that this was an issue on pure Linux and upstream thinks that it could potentially be an issue in Android-specific kernel changes",
					"mdeslaur> The android package is in multiverse and not covered by ESM.",
					"mdeslaur> Marking as ignored.",
				},
				Patches: map[Package]Statuses{
					Package("test-package"): {
						"upstream": Status{
							Status: "needs-triage",
						},
					},
				},
				UpstreamLinks: map[Package][]string{},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.Open(tc.args.filePath)
			require.NoError(t, err)
			defer f.Close()

			got, gotErr := parse(f)
			assert.Equal(t, tc.wantErr, gotErr)
			assert.Equal(t, tc.want, got)
		})
	}
}
