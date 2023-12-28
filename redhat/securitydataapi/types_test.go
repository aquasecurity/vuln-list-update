package securitydataapi_test

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/kylelemons/godebug/pretty"

	"github.com/aquasecurity/vuln-list-update/redhat/securitydataapi"
)

func TestRedhatCVEJSON_UnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		in   string
		want *securitydataapi.RedhatCVEJSON
	}{
		"mitigation_string": {
			in: "testdata/CVE-2019-7614.json",
			want: &securitydataapi.RedhatCVEJSON{
				ThreatSeverity: "Low",
				PublicDate:     "2019-07-31T00:00:00",
				Bugzilla: securitydataapi.RedhatBugzilla{
					RedhatCVEID: 0,
					Description: "\nCVE-2019-7614 elasticsearch: Race condition in response headers on systems with multiple submitting requests\n    ",
					BugzillaID:  "1747240",
					URL:         "https://bugzilla.redhat.com/show_bug.cgi?id=1747240",
				},
				Cvss: securitydataapi.RedhatCvss{
					RedhatCVEID:       0,
					CvssBaseScore:     "",
					CvssScoringVector: "",
					Status:            "",
				},
				Cvss3: securitydataapi.RedhatCvss3{
					RedhatCVEID:        0,
					Cvss3BaseScore:     "2.0",
					Cvss3ScoringVector: "CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N",
					Status:             "draft",
				},
				Iava:            "",
				Cwe:             "CWE-362",
				Statement:       "\nRed Hat JBoss Fuse 6: \nThis vulnerability has been rated as having a security impact of Low. After evaluation and in accordance with the criteria noted in the product support life cycle, there are no plans to address this issue in an upcoming release. Please contact Red Hat Support for further information.\n    ",
				Acknowledgement: "",
				Mitigation:      "\nThere is no mitigation for this issue, the flaw can only be resolved by applying updates.\n    ",
				PackageState: []securitydataapi.RedhatPackageState{
					{
						RedhatCVEID: 0,
						ProductName: "Red Hat JBoss Fuse 6",
						FixState:    "Out of support scope",
						PackageName: "elasticsearch",
						Cpe:         "cpe:/a:redhat:jboss_fuse:6",
					},
					{
						RedhatCVEID: 0,
						ProductName: "Red Hat JBoss Fuse 7",
						FixState:    "New",
						PackageName: "elasticsearch",
						Cpe:         "cpe:/a:redhat:jboss_fuse:7",
					},
				},
				//AffectedRelease:      []securitydataapi.RedhatAffectedRelease{},
				Name:                 "CVE-2019-7614",
				DocumentDistribution: "",
				Details: []string{
					"\nA race condition flaw was found in the response headers Elasticsearch versions before 7.2.1 and 6.8.2 returns to a request. On a system with multiple users submitting requests, it could be possible for an attacker to gain access to response header containing sensitive data from another user.\n    ",
				},
				//References: []string{},
			},
		},
		"mitigation_object": {
			in: "testdata/CVE-2009-2694.json",
			want: &securitydataapi.RedhatCVEJSON{
				ThreatSeverity: "Critical",
				PublicDate:     "2009-08-18T00:00:00Z",
				Bugzilla: securitydataapi.RedhatBugzilla{
					RedhatCVEID: 0,
					Description: "\nCVE-2009-2694 pidgin: insufficient input validation in msn_slplink_process_msg()\n    ",
					BugzillaID:  "514957",
					URL:         "https://bugzilla.redhat.com/show_bug.cgi?id=514957",
				},
				Cvss: securitydataapi.RedhatCvss{
					RedhatCVEID:       0,
					CvssBaseScore:     "7.5",
					CvssScoringVector: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
					Status:            "verified",
				},
				Cvss3: securitydataapi.RedhatCvss3{
					RedhatCVEID:        0,
					Cvss3BaseScore:     "",
					Cvss3ScoringVector: "",
					Status:             "",
				},
				Iava:            "",
				Cwe:             "CWE-228->CWE-119",
				Statement:       "",
				Acknowledgement: "",
				Mitigation:      "\nUsers can lower the impact of this flaw by making sure their privacy settings only allow Pidgin to accept messages from the users on their buddy list.  This will prevent exploitation of this flaw by other random MSN users.\n    ",
				AffectedRelease: []securitydataapi.RedhatAffectedRelease{
					{
						RedhatCVEID: 0,
						ProductName: "Red Hat Enterprise Linux 3",
						ReleaseDate: "2009-08-18T00:00:00Z",
						Advisory:    "RHSA-2009:1218",
						Package:     "pidgin-1.5.1-4.el3",
						Cpe:         "cpe:/o:redhat:enterprise_linux:3",
					},
				},
				Name:                 "CVE-2009-2694",
				DocumentDistribution: "",
				Details: []string{
					"\nThe msn_slplink_process_msg function in libpurple/protocols/msn/slplink.c in libpurple, as used in Pidgin (formerly Gaim) before 2.5.9 and Adium 1.3.5 and earlier, allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption and application crash) by sending multiple crafted SLP (aka MSNSLP) messages to trigger an overwrite of an arbitrary memory location.  NOTE: this issue reportedly exists because of an incomplete fix for CVE-2009-1376.\n    ",
				},
			},
		},
	}
	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			jsonByte, err := os.ReadFile(tt.in)
			if err != nil {
				t.Fatalf("unknown error: %s", err)
			}

			got := &securitydataapi.RedhatCVEJSON{}
			err = json.Unmarshal(jsonByte, got)
			if err != nil {
				t.Fatalf("unknown error: %s", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("[%s]\n diff: %s", testname, pretty.Compare(got, tt.want))
			}
		})
	}
}
