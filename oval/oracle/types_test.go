package oracle_test

import (
	"encoding/xml"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/aquasecurity/vuln-list-update/oval/oracle"
	"github.com/kylelemons/godebug/pretty"
)

func TestRedhatCVEJSON_UnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		in   string
		want *oracle.Oval
	}{
		"nested_criterias_elsa_data": {
			// https://linux.oracle.com/oval/com.oracle.elsa-20070057.xml
			in: "testdata/ELSA-2007-0057.xml",
			want: &oracle.Oval{
				[]oracle.Definition{
					oracle.Definition{
						Title:       "\nELSA-2007-0057:  Moderate: bind security update  (MODERATE)\n",
						Description: "\n [30:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229 \n",
						Platform:    []string{"Oracle Linux 5"},
						References: []oracle.Reference{
							oracle.Reference{
								Source: "elsa",
								URI:    "http://linux.oracle.com/errata/ELSA-2007-0057.html",
								ID:     "ELSA-2007-0057",
							},
							oracle.Reference{
								Source: "CVE",
								URI:    "http://linux.oracle.com/cve/CVE-2007-0493.html",
								ID:     "CVE-2007-0493",
							},
							oracle.Reference{
								Source: "CVE",
								URI:    "http://linux.oracle.com/cve/CVE-2007-0494.html",
								ID:     "CVE-2007-0494",
							},
						},
						Criteria: oracle.Criteria{
							Operator: "AND",
							Criterias: []*oracle.Criteria{
								&oracle.Criteria{
									Operator: "OR",
									Criterias: []*oracle.Criteria{
										&oracle.Criteria{
											Operator:  "AND",
											Criterias: nil,
											Criterions: []oracle.Criterion{
												oracle.Criterion{
													Comment: "bind-devel is earlier than 30:9.3.3-8.el5",
												},
												oracle.Criterion{
													Comment: "bind-devel is signed with the Oracle Linux 5 key",
												},
											},
										},
										&oracle.Criteria{
											Operator:  "AND",
											Criterias: nil,
											Criterions: []oracle.Criterion{
												oracle.Criterion{
													Comment: "bind-sdb is earlier than 30:9.3.3-8.el5",
												},
												oracle.Criterion{
													Comment: "bind-sdb is signed with the Oracle Linux 5 key",
												},
											},
										},
										&oracle.Criteria{
											Operator:  "AND",
											Criterias: nil,
											Criterions: []oracle.Criterion{
												oracle.Criterion{
													Comment: "bind-libs is earlier than 30:9.3.3-8.el5",
												},
												oracle.Criterion{
													Comment: "bind-libs is signed with the Oracle Linux 5 key",
												},
											},
										},
										&oracle.Criteria{
											Operator:  "AND",
											Criterias: nil,
											Criterions: []oracle.Criterion{
												oracle.Criterion{
													Comment: "bind-libbind-devel is earlier than 30:9.3.3-8.el5",
												},
												oracle.Criterion{
													Comment: "bind-libbind-devel is signed with the Oracle Linux 5 key",
												},
											},
										},
										&oracle.Criteria{
											Operator:  "AND",
											Criterias: nil,
											Criterions: []oracle.Criterion{
												oracle.Criterion{
													Comment: "bind-utils is earlier than 30:9.3.3-8.el5",
												},
												oracle.Criterion{
													Comment: "bind-utils is signed with the Oracle Linux 5 key",
												},
											},
										},
										&oracle.Criteria{
											Operator:  "AND",
											Criterias: nil,
											Criterions: []oracle.Criterion{
												oracle.Criterion{
													Comment: "bind-chroot is earlier than 30:9.3.3-8.el5",
												},
												oracle.Criterion{
													Comment: "bind-chroot is signed with the Oracle Linux 5 key",
												},
											},
										},
										&oracle.Criteria{
											Operator:  "AND",
											Criterias: nil,
											Criterions: []oracle.Criterion{
												oracle.Criterion{
													Comment: "bind is earlier than 30:9.3.3-8.el5",
												},
												oracle.Criterion{
													Comment: "bind is signed with the Oracle Linux 5 key",
												},
											},
										},
										&oracle.Criteria{
											Operator:  "AND",
											Criterias: nil,
											Criterions: []oracle.Criterion{
												oracle.Criterion{
													Comment: "caching-nameserver is earlier than 30:9.3.3-8.el5",
												},
												oracle.Criterion{
													Comment: "caching-nameserver is signed with the Oracle Linux 5 key",
												},
											},
										},
									},
									Criterions: nil,
								},
							},
							Criterions: []oracle.Criterion{
								oracle.Criterion{
									Comment: "Oracle Linux 5 is installed",
								},
							},
						},
						Severity: "MODERATE",
						CVEs: []oracle.Cve{
							oracle.Cve{
								Impact: "",
								Href:   "http://linux.oracle.com/cve/CVE-2007-0493.html",
								ID:     "CVE-2007-0493",
							},
							oracle.Cve{
								Impact: "",
								Href:   "http://linux.oracle.com/cve/CVE-2007-0494.html",
								ID:     "CVE-2007-0494",
							},
						},
					},
				},
			},
		},
	}
	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			xmlByte, err := ioutil.ReadFile(tt.in)
			if err != nil {
				t.Fatalf("unknown error: %s", err)
			}

			got := &oracle.Oval{}
			err = xml.Unmarshal(xmlByte, got)
			if err != nil {
				t.Fatalf("unknown error: %s", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("[%s]\n diff: %s", testname, pretty.Compare(got, tt.want))
			}
		})
	}
}
