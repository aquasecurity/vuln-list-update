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
						"upstream": Status{
							Status: "needs-triage",
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
