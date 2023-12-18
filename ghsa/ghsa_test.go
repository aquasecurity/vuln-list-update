package ghsa

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"testing"
	"time"

	githubql "github.com/shurcooL/githubv4"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "update golden files")

type MockClient struct {
	Response   map[githubql.String]GetVulnerabilitiesQuery
	Error      error
	ErrorCount int
}

func (mc MockClient) Query(ctx context.Context, q interface{}, variables map[string]interface{}) error {
	if mc.Error != nil {
		return mc.Error
	}

	cursor := variables["cursor"].(*githubql.String)
	if cursor == (*githubql.String)(nil) {
		q.(*GetVulnerabilitiesQuery).SecurityVulnerabilities = mc.Response[githubql.String("")].SecurityVulnerabilities
		return nil
	}

	q.(*GetVulnerabilitiesQuery).SecurityVulnerabilities = mc.Response[*cursor].SecurityVulnerabilities
	return nil
}

func TestConfig_Update(t *testing.T) {
	testCases := []struct {
		name             string
		appFs            afero.Fs
		inputEcosystem   SecurityAdvisoryEcosystem
		goldenFiles      map[string]string
		inputResponse    map[githubql.String]GetVulnerabilitiesQuery
		expectedErrorMsg string
	}{
		{
			name:           "positive test",
			appFs:          afero.NewMemMapFs(),
			inputEcosystem: Composer,
			goldenFiles: map[string]string{
				"/tmp/ghsa/composer/simplesamlphp/simplesamlphp/GHSA-2r3v-q9x3-7g46.json": "testdata/composer/simplesamlphp/simplesamlphp/GHSA-2r3v-q9x3-7g46.json",
			},
			inputResponse: map[githubql.String]GetVulnerabilitiesQuery{
				githubql.String(""): {
					SecurityVulnerabilities: SecurityVulnerabilities{
						Nodes: []GithubSecurityAdvisory{
							{
								Severity:  "LOW",
								UpdatedAt: "2020-01-24T21:15:59Z",
								Package: Package{
									Ecosystem: "COMPOSER",
									Name:      "simplesamlphp/simplesamlphp",
								},
								Advisory: Advisory{
									DatabaseId: 1883,
									Id:         "MDE2OlNlY3VyaXR5QWR2aXNvcnlHSFNBLTJyM3YtcTl4My03ZzQ2",
									GhsaId:     "GHSA-2r3v-q9x3-7g46",
									References: []Reference{
										{
											Url: "https://github.com/simplesamlphp/simplesamlphp/security/advisories/GHSA-2r3v-q9x3-7g46",
										},
									},
									Identifiers: []Identifier{
										{
											Type:  "GHSA",
											Value: "GHSA-2r3v-q9x3-7g46",
										},
									},
									Description: "### Background\nSeveral scripts part of SimpleSAMLphp display a web page with links obtained from the request parameters. This allows us to enhance usability, as the users are presented with links they can follow after completing a certain action, like logging out.\n\n### Description\nThe following scripts were not checking the URLs obtained via the HTTP request before displaying them as the target of links that the user may click on:\n\n- `www/logout.php`\n- `modules/core/www/no_cookie.php`\n\nThe issue allowed attackers to display links targeting a malicious website inside a trusted site running SimpleSAMLphp, due to the lack of security checks involving the `link_href` and `retryURL` HTTP parameters, respectively. The issue was resolved by including a verification of the URLs received in the request against a white list of websites specified in the `trusted.url.domains` configuration option.\n\n### Affected versions\nAll SimpleSAMLphp versions prior to 1.14.4.\n\n### Impact\nA remote attacker could craft a link pointing to a trusted website running SimpleSAMLphp, including a parameter pointing to a malicious website, and try to fool the victim into visiting that website by clicking on a link in the page presented by SimpleSAMLphp.\n\n### Resolution\nUpgrade to the latest version.\n\n### Credit\nThis security issue was discovered and reported by John Page (hyp3rlinx).",
									Origin:      "UNSPECIFIED",
									PublishedAt: "2020-01-24T21:27:16Z",
									Severity:    "LOW",
									Summary:     "Low severity vulnerability that affects simplesamlphp/simplesamlphp",
									UpdatedAt:   "2020-01-24T21:27:17Z",
									WithdrawnAt: "",
									CVSS: GithubCVSS{
										Score:        3.7,
										VectorString: "3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
									},
								},
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "1.14.4",
								},
								VulnerableVersionRange: "\u003c 1.14.4",
							},
						},
						PageInfo: PageInfo{
							EndCursor:   githubql.String(""),
							HasNextPage: false,
						},
					},
				},
			},
		},
		{
			name:           "positive test with one nil node",
			appFs:          afero.NewMemMapFs(),
			inputEcosystem: Composer,
			goldenFiles: map[string]string{
				"/tmp/ghsa/composer/simplesamlphp/simplesamlphp/GHSA-2r3v-q9x3-7g46.json": "testdata/composer/simplesamlphp/simplesamlphp/GHSA-2r3v-q9x3-7g46.json",
			},
			inputResponse: map[githubql.String]GetVulnerabilitiesQuery{
				githubql.String(""): {
					SecurityVulnerabilities: SecurityVulnerabilities{
						Nodes: []GithubSecurityAdvisory{
							{
								Severity:  "LOW",
								UpdatedAt: "2020-01-24T21:15:59Z",
								Package: Package{
									Ecosystem: "COMPOSER",
									Name:      "simplesamlphp/simplesamlphp",
								},
								Advisory: Advisory{
									DatabaseId: 1883,
									Id:         "MDE2OlNlY3VyaXR5QWR2aXNvcnlHSFNBLTJyM3YtcTl4My03ZzQ2",
									GhsaId:     "GHSA-2r3v-q9x3-7g46",
									References: []Reference{
										{
											Url: "https://github.com/simplesamlphp/simplesamlphp/security/advisories/GHSA-2r3v-q9x3-7g46",
										},
									},
									Identifiers: []Identifier{
										{
											Type:  "GHSA",
											Value: "GHSA-2r3v-q9x3-7g46",
										},
									},
									Description: "### Background\nSeveral scripts part of SimpleSAMLphp display a web page with links obtained from the request parameters. This allows us to enhance usability, as the users are presented with links they can follow after completing a certain action, like logging out.\n\n### Description\nThe following scripts were not checking the URLs obtained via the HTTP request before displaying them as the target of links that the user may click on:\n\n- `www/logout.php`\n- `modules/core/www/no_cookie.php`\n\nThe issue allowed attackers to display links targeting a malicious website inside a trusted site running SimpleSAMLphp, due to the lack of security checks involving the `link_href` and `retryURL` HTTP parameters, respectively. The issue was resolved by including a verification of the URLs received in the request against a white list of websites specified in the `trusted.url.domains` configuration option.\n\n### Affected versions\nAll SimpleSAMLphp versions prior to 1.14.4.\n\n### Impact\nA remote attacker could craft a link pointing to a trusted website running SimpleSAMLphp, including a parameter pointing to a malicious website, and try to fool the victim into visiting that website by clicking on a link in the page presented by SimpleSAMLphp.\n\n### Resolution\nUpgrade to the latest version.\n\n### Credit\nThis security issue was discovered and reported by John Page (hyp3rlinx).",
									Origin:      "UNSPECIFIED",
									PublishedAt: "2020-01-24T21:27:16Z",
									Severity:    "LOW",
									Summary:     "Low severity vulnerability that affects simplesamlphp/simplesamlphp",
									UpdatedAt:   "2020-01-24T21:27:17Z",
									WithdrawnAt: "",
									CVSS: GithubCVSS{
										Score:        3.7,
										VectorString: "3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
									},
								},
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "1.14.4",
								},
								VulnerableVersionRange: "\u003c 1.14.4",
							},
							{}, // nil node
						},
						PageInfo: PageInfo{
							EndCursor:   githubql.String(""),
							HasNextPage: false,
						},
					},
				},
			},
		},
		{
			name:           "positive test multi nodes",
			appFs:          afero.NewMemMapFs(),
			inputEcosystem: Maven,
			goldenFiles: map[string]string{
				"/tmp/ghsa/maven/org.apache.solr/solr-core/GHSA-2289-pqfq-6wx7.json":   "testdata/maven/org.apache.solr/solr-core/GHSA-2289-pqfq-6wx7.json",
				"/tmp/ghsa/maven/org.apache.qpid/qpid-broker/GHSA-269m-695x-j34p.json": "testdata/maven/org.apache.qpid/qpid-broker/GHSA-269m-695x-j34p.json",
				"/tmp/ghsa/maven/org.apache.hive/hive/GHSA-2g9q-chq2-w8qw.json":        "testdata/maven/org.apache.hive/hive/GHSA-2g9q-chq2-w8qw.json",
			},
			inputResponse: map[githubql.String]GetVulnerabilitiesQuery{
				githubql.String(""): {
					SecurityVulnerabilities: SecurityVulnerabilities{
						Nodes: []GithubSecurityAdvisory{
							{
								Severity:  "HIGH",
								UpdatedAt: "2020-01-28T22:25:34Z",
								Package: Package{
									Ecosystem: "MAVEN",
									Name:      "org.apache.solr:solr-core",
								},
								Advisory: Advisory{
									DatabaseId: 1892,
									Id:         "MDE2OlNlY3VyaXR5QWR2aXNvcnlHSFNBLTIyODktcHFmcS02d3g3",
									GhsaId:     "GHSA-2289-pqfq-6wx7",
									References: []Reference{
										{
											Url: "https://nvd.nist.gov/vuln/detail/CVE-2019-12409",
										},
									},
									Identifiers: []Identifier{
										{
											Type:  "GHSA",
											Value: "GHSA-2289-pqfq-6wx7",
										},
										{
											Type:  "CVE",
											Value: "CVE-2019-12409",
										},
									},
									Description: "The 8.1.1 and 8.2.0 releases of Apache Solr contain an insecure setting for the ENABLE_REMOTE_JMX_OPTS configuration option in the default solr.in.sh configuration file shipping with Solr. If you use the default solr.in.sh file from the affected releases, then JMX monitoring will be enabled and exposed on RMI_PORT (default=18983), without any authentication. If this port is opened for inbound traffic in your firewall, then anyone with network access to your Solr nodes will be able to access JMX, which may in turn allow them to upload malicious code for execution on the Solr server.",
									Origin:      "UNSPECIFIED",
									PublishedAt: "2020-01-28T22:26:54Z",
									Severity:    "HIGH",
									Summary:     "High severity vulnerability that affects org.apache.solr:solr-core",
									UpdatedAt:   "2020-01-28T22:26:54Z",
									WithdrawnAt: "",
									CVSS: GithubCVSS{
										Score:        9.8,
										VectorString: "3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
									},
								},
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "8.3.0",
								},
								VulnerableVersionRange: "\u003e= 8.1.1, \u003c= 8.2.0",
							},
							{
								Severity:  "MODERATE",
								UpdatedAt: "2018-10-19T16:40:55Z",
								Package: Package{
									Ecosystem: "MAVEN",
									Name:      "org.apache.qpid:qpid-broker",
								},
								Advisory: Advisory{
									DatabaseId: 888,
									Id:         "MDE2OlNlY3VyaXR5QWR2aXNvcnlHSFNBLTI2OW0tNjk1eC1qMzRw",
									GhsaId:     "GHSA-269m-695x-j34p",
									References: []Reference{
										{
											Url: "https://nvd.nist.gov/vuln/detail/CVE-2017-15702",
										},
									},
									Identifiers: []Identifier{
										{
											Type:  "GHSA",
											Value: "GHSA-269m-695x-j34p",
										},
										{
											Type:  "CVE",
											Value: "CVE-2017-15702",
										},
									},
									Description: "In Apache Qpid Broker-J 0.18 through 0.32, if the broker is configured with different authentication providers on different ports one of which is an HTTP port, then the broker can be tricked by a remote unauthenticated attacker connecting to the HTTP port into using an authentication provider that was configured on a different port. The attacker still needs valid credentials with the authentication provider on the spoofed port. This becomes an issue when the spoofed port has weaker authentication protection (e.g., anonymous access, default accounts) and is normally protected by firewall rules or similar which can be circumvented by this vulnerability. AMQP ports are not affected. Versions 6.0.0 and newer are not affected.",
									Origin:      "UNSPECIFIED",
									PublishedAt: "2018-10-19T16:41:04Z",
									Severity:    "MODERATE",
									Summary:     "Moderate severity vulnerability that affects org.apache.qpid:qpid-broker",
									UpdatedAt:   "2019-07-03T21:02:04Z",
									WithdrawnAt: "",
									CVSS: GithubCVSS{
										Score:        9.8,
										VectorString: "3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
									},
								},
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "6.0.0",
								},
								VulnerableVersionRange: "\u003e= 0.18, \u003c= 0.32",
							},
						},
						PageInfo: PageInfo{
							EndCursor:   githubql.String("nextCursor"),
							HasNextPage: true,
						},
					},
				},
				githubql.String("nextCursor"): {
					SecurityVulnerabilities: SecurityVulnerabilities{
						Nodes: []GithubSecurityAdvisory{
							{

								Severity:  "MODERATE",
								UpdatedAt: "2019-03-14T15:37:54Z",
								Package: Package{
									Ecosystem: "MAVEN",
									Name:      "org.apache.hive:hive",
								},
								Advisory: Advisory{
									DatabaseId: 1293,
									Id:         "MDE2OlNlY3VyaXR5QWR2aXNvcnlHSFNBLTJnOXEtY2hxMi13OHF3",
									GhsaId:     "GHSA-2g9q-chq2-w8qw",
									References: []Reference{
										{
											Url: "https://nvd.nist.gov/vuln/detail/CVE-2017-12625",
										},
									},
									Identifiers: []Identifier{
										{
											Type:  "GHSA",
											Value: "GHSA-2g9q-chq2-w8qw",
										},
										{
											Type:  "CVE",
											Value: "CVE-2017-12625",
										},
									},
									Description: "Apache Hive 2.1.x before 2.1.2, 2.2.x before 2.2.1, and 2.3.x before 2.3.1 expose an interface through which masking policies can be defined on tables or views, e.g., using Apache Ranger. When a view is created over a given table, the policy enforcement does not happen correctly on the table for masked columns.",
									Origin:      "UNSPECIFIED",
									PublishedAt: "2019-03-14T15:40:16Z",
									Severity:    "MODERATE",
									Summary:     "Moderate severity vulnerability that affects org.apache.hive:hive, org.apache.hive:hive-exec, and org.apache.hive:hive-service",
									UpdatedAt:   "2019-07-03T21:02:07Z",
									WithdrawnAt: "",
									CVSS: GithubCVSS{
										Score:        4.3,
										VectorString: "3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
									},
								},
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "2.3.1",
								},
								VulnerableVersionRange: "= 2.3.0",
							},
							{

								Severity:  "MODERATE",
								UpdatedAt: "2019-03-14T15:37:54Z",
								Package: Package{
									Ecosystem: "MAVEN",
									Name:      "org.apache.hive:hive",
								},
								Advisory: Advisory{
									DatabaseId: 1293,
									Id:         "MDE2OlNlY3VyaXR5QWR2aXNvcnlHSFNBLTJnOXEtY2hxMi13OHF3",
									GhsaId:     "GHSA-2g9q-chq2-w8qw",
									References: []Reference{
										{
											Url: "https://nvd.nist.gov/vuln/detail/CVE-2017-12625",
										},
									},
									Identifiers: []Identifier{
										{
											Type:  "GHSA",
											Value: "GHSA-2g9q-chq2-w8qw",
										},
										{
											Type:  "CVE",
											Value: "CVE-2017-12625",
										},
									},
									Description: "Apache Hive 2.1.x before 2.1.2, 2.2.x before 2.2.1, and 2.3.x before 2.3.1 expose an interface through which masking policies can be defined on tables or views, e.g., using Apache Ranger. When a view is created over a given table, the policy enforcement does not happen correctly on the table for masked columns.",
									Origin:      "UNSPECIFIED",
									PublishedAt: "2019-03-14T15:40:16Z",
									Severity:    "MODERATE",
									Summary:     "Moderate severity vulnerability that affects org.apache.hive:hive, org.apache.hive:hive-exec, and org.apache.hive:hive-service",
									UpdatedAt:   "2019-07-03T21:02:07Z",
									WithdrawnAt: "",
									CVSS: GithubCVSS{
										Score:        4.3,
										VectorString: "3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
									},
								},
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "2.2.1",
								},
								VulnerableVersionRange: "= 2.2.0",
							},
							{

								Severity:  "MODERATE",
								UpdatedAt: "2019-03-14T15:37:54Z",
								Package: Package{
									Ecosystem: "MAVEN",
									Name:      "org.apache.hive:hive",
								},
								Advisory: Advisory{
									DatabaseId: 1293,
									Id:         "MDE2OlNlY3VyaXR5QWR2aXNvcnlHSFNBLTJnOXEtY2hxMi13OHF3",
									GhsaId:     "GHSA-2g9q-chq2-w8qw",
									References: []Reference{
										{
											Url: "https://nvd.nist.gov/vuln/detail/CVE-2017-12625",
										},
									},
									Identifiers: []Identifier{
										{
											Type:  "GHSA",
											Value: "GHSA-2g9q-chq2-w8qw",
										},
										{
											Type:  "CVE",
											Value: "CVE-2017-12625",
										},
									},
									Description: "Apache Hive 2.1.x before 2.1.2, 2.2.x before 2.2.1, and 2.3.x before 2.3.1 expose an interface through which masking policies can be defined on tables or views, e.g., using Apache Ranger. When a view is created over a given table, the policy enforcement does not happen correctly on the table for masked columns.",
									Origin:      "UNSPECIFIED",
									PublishedAt: "2019-03-14T15:40:16Z",
									Severity:    "MODERATE",
									Summary:     "Moderate severity vulnerability that affects org.apache.hive:hive, org.apache.hive:hive-exec, and org.apache.hive:hive-service",
									UpdatedAt:   "2019-07-03T21:02:07Z",
									WithdrawnAt: "",
									CVSS: GithubCVSS{
										Score:        4.3,
										VectorString: "3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
									},
								},
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "2.1.2",
								},
								VulnerableVersionRange: "\u003e= 2.1.0, \u003c 2.1.2",
							},
						},
						PageInfo: PageInfo{
							EndCursor:   githubql.String(""),
							HasNextPage: false,
						},
					},
				},
			},
			expectedErrorMsg: "",
		},
		{
			name:           "happy path with correct swift dir name",
			appFs:          afero.NewMemMapFs(),
			inputEcosystem: Swift,
			goldenFiles: map[string]string{
				"/tmp/ghsa/swift/github.com/grpc/grpc-swift/GHSA-r6ww-5963-7r95.json": "testdata/swift/github.com/grpc/grpc-swift/GHSA-r6ww-5963-7r95.json",
			},
			inputResponse: map[githubql.String]GetVulnerabilitiesQuery{
				githubql.String(""): {
					SecurityVulnerabilities: SecurityVulnerabilities{
						Nodes: []GithubSecurityAdvisory{
							{
								Severity:  "HIGH",
								UpdatedAt: "2023-06-09T19:33:17Z",
								Package: Package{
									Ecosystem: "SWIFT",
									Name:      "https://github.com/grpc/grpc-swift.git",
								},
								Advisory: Advisory{
									DatabaseId: 212034,
									Id:         "GSA_kwCzR0hTQS1yNnd3LTU5NjMtN3I5Nc4AAzxC",
									GhsaId:     "GHSA-r6ww-5963-7r95",
									References: []Reference{
										{
											Url: "https://github.com/grpc/grpc-swift/security/advisories/GHSA-r6ww-5963-7r95",
										},
										{
											Url: "https://nvd.nist.gov/vuln/detail/CVE-2022-24777",
										},
										{
											Url: "https://github.com/grpc/grpc-swift/commit/858f977f2a51fca2292f384cf7a108dc2e73a3bd",
										},
										{
											Url: "https://github.com/advisories/GHSA-r6ww-5963-7r95",
										},
									},
									Identifiers: []Identifier{
										{
											Type:  "GHSA",
											Value: "GHSA-r6ww-5963-7r95",
										},
										{
											Type:  "CVE",
											Value: "CVE-2022-24777",
										},
									},
									Description: "A grpc-swift server is vulnerable to a denial of service attack via a reachable assertion. This was due to incorrect logic when handling `GOAWAY` frames.\n\nThe attack is low-effort: it takes very little resources to construct and send the required sequence of frames. The impact on availability is high as the server will crash, dropping all in flight connections and requests.\n\nThe issue was discovered by automated fuzz testing and is resolved by fixing the relevant state handling code.",
									Origin:      "UNSPECIFIED",
									PublishedAt: "2023-06-09T19:33:16Z",
									Severity:    "HIGH",
									Summary:     "Denial of Service via reachable assertion",
									UpdatedAt:   "2023-06-19T16:45:07Z",
									WithdrawnAt: "",
									CVSS: GithubCVSS{
										Score:        7.5,
										VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
									},
								},
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "1.7.2",
								},
								VulnerableVersionRange: "\u003c 1.7.2",
							},
						},
						PageInfo: PageInfo{
							EndCursor:   githubql.String(""),
							HasNextPage: false,
						},
					},
				},
			},
		},
		{
			name:           "read only filesystem test",
			appFs:          afero.NewReadOnlyFs(afero.NewOsFs()),
			inputEcosystem: Composer,
			goldenFiles:    map[string]string{},
			inputResponse: map[githubql.String]GetVulnerabilitiesQuery{
				githubql.String(""): {
					SecurityVulnerabilities: SecurityVulnerabilities{
						Nodes: []GithubSecurityAdvisory{
							{
								Package: Package{
									Ecosystem: "COMPOSER",
									Name:      "composer",
								},
								Advisory: Advisory{
									DatabaseId: 1,
								},
							},
						},
						PageInfo: PageInfo{
							EndCursor:   githubql.String(""),
							HasNextPage: false,
						},
					},
				},
			},
			expectedErrorMsg: "unable to create a directory: operation not permitted",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := MockClient{
				Response: tc.inputResponse,
			}
			c := Config{
				vulnListDir: "/tmp",
				appFs:       tc.appFs,
				retry:       0,
				client:      client,
			}
			err := c.update(tc.inputEcosystem)
			switch {
			case tc.expectedErrorMsg != "":
				require.NotNil(t, err, tc.name)
				assert.Contains(t, err.Error(), tc.expectedErrorMsg, tc.name)
				return
			default:
				assert.NoError(t, err, tc.name)
			}

			fileCount := 0
			err = afero.Walk(c.appFs, "/", func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				fileCount += 1

				actual, err := afero.ReadFile(c.appFs, path)
				assert.NoError(t, err, tc.name)

				goldenPath, ok := tc.goldenFiles[path]
				if !ok {
					fmt.Println(path)
				}
				assert.True(t, ok, tc.name)

				if *update {
					err = os.WriteFile(goldenPath, actual, 0666)
					assert.NoError(t, err, tc.name)
				}

				expected, err := os.ReadFile(goldenPath)
				assert.NoError(t, err, tc.name)

				assert.Equal(t, string(expected), string(actual), tc.name)

				return nil
			})
			assert.Equal(t, len(tc.goldenFiles), fileCount, tc.name)
			assert.NoError(t, err, tc.name)
		})
	}

}

func TestConfig_FetchGithubSecurityAdvisories(t *testing.T) {
	testCases := []struct {
		name  string
		retry int
	}{
		{
			name:  "retry test",
			retry: 1,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			wait = func(i int) time.Duration { return 0 }
			client := MockClient{
				Error: errors.New("request error"),
			}
			c := Config{
				vulnListDir: "/tmp",
				appFs:       afero.NewMemMapFs(),
				retry:       tc.retry,
				client:      client,
			}
			_, err := c.fetchGithubSecurityAdvisories(Pip)
			assert.Error(t, err, tc.name)
		})
	}
}
