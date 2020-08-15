package ubuntu

import (
	"github.com/araddon/dateparse"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"reflect"
	"testing"
)

func Test_parse(t *testing.T) {
	publicationDate, err := dateparse.ParseAny("2007-01-16 23:28:00 UTC")
	require.Nil(t, err)
	type args struct {
		fileReader io.Reader
	}
	emptyStatusUpstreamFile, err := os.Open("./testdata/empty_status_upstream")
	require.Nil(t, err)
	defer emptyStatusUpstreamFile.Close()
	lineBreakBetweenPatched, err := os.Open("./testdata/line_break_between_patches")
	require.Nil(t, err)
	defer lineBreakBetweenPatched.Close()
	moreThanOnePackagePatches, err := os.Open("./testdata/more_than_one_package_patches")
	require.Nil(t, err)
	defer moreThanOnePackagePatches.Close()
	testCases := []struct {
		name     string
		args     args
		wantVuln *Vulnerability
		wantErr  error
	}{
		{
			name: "when empty upstream patch is passed",
			args: args{
				fileReader: emptyStatusUpstreamFile,
			},
			wantVuln: &Vulnerability{
				Candidate:   "CVE-2007-0255",
				References:  []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0255"},
				Description: "XINE 0.99.4 allows user-assisted remote attackers to cause a denial of service (application crash) and possibly execute arbitrary code via a certain M3U file that contains a long #EXTINF line and contains format string specifiers in an invalid udp:// URI, possibly a variant of CVE-2007-0017.",
				PublicDate:  publicationDate,
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
				fileReader: lineBreakBetweenPatched,
			},
			wantVuln: &Vulnerability{
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
				PublicDate:   publicationDate,
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
				fileReader: moreThanOnePackagePatches,
			},
			wantVuln: &Vulnerability{
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
				PublicDate: publicationDate,
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
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotVuln, gotErr := parse(tc.args.fileReader)
			if !reflect.DeepEqual(gotVuln, tc.wantVuln) {
				t.Errorf("ubuntu_parse: gotVulnerability = %v, want %v", gotVuln, tc.wantVuln)
			}
			if !reflect.DeepEqual(gotErr, tc.wantErr) {
				t.Errorf("ubuntu_parse: gotErr = %v, want %v", gotErr, tc.wantErr)
			}
		})
	}
}
