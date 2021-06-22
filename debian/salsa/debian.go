package salsa

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"

	"golang.org/x/xerrors"

	"github.com/cheggaaa/pb"
	"github.com/pkg/errors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	cloneCmd           = "clone --depth 1 https://salsa.debian.org/security-tracker-team/security-tracker.git"
	debianDir          = "debian-salsa"
	coveredReleasesURL = "http://security-tracker.debian.org/tracker/data/releases"
	releasesURL        = "http://www.debian.org/releases/"
)

var releaseRegexp = regexp.MustCompile(`Debian (?:GNU/Linux )?(\d+)`)

type dsa struct {
	name        string
	date        time.Time
	description string
	cves        []string
	packages    []pkg
}

type pkg struct {
	release, name, version, severity, statement string
	willNotFix                                  bool
	classification                              int64
	severityClassification                      string
}

type cve struct {
	name     string
	reserved bool
	notForUs bool
	packages []pkg
	notes    []string
}

var (
	dsaLine     = regexp.MustCompile(`^\[(\d\d \w{3} \d{4})\] (D(?:S|L)A-\d+(?:-\d+)?)\s*(.*)`)
	dsaCVEsLine = regexp.MustCompile(`(CVE-\d+-\d+)`)
	dsaPkgLine  = regexp.MustCompile(`^\s*(?:\[(\w+)\]\s*)?- ([^\s]+) ([^\s]+)$`)
)

var (
	cveLine      = regexp.MustCompile(`^(CVE-\d+-[0-9X]+)`)
	notForUsLine = regexp.MustCompile(`^\s*NOT-FOR-US`)
	noteLine     = regexp.MustCompile(`^\s*NOTE:\s*(.+)$`)
	reservedLine = regexp.MustCompile(`^\s*RESERVED`)
	packageLine  = regexp.MustCompile(`^\s*(?:\[(\w+)\]\s*)?- ([^\s]+) ([^\s]+)(?: \(([^\)]+)\))?`)
	bugNumber    = regexp.MustCompile(`\s*;?\s*bug\s*#\d+\s*;?\s*`)
)

type DebianSalsa struct {
	cloneCommand string
	VulnListDir  string
	oss          map[string]string
	cveToDSA     map[string][]dsa
	PackageData  map[string]map[string]CVERelease
}

type CVERelease struct {
	Description string                    `json:"description"`
	Releases    map[string]ReleaseDetails `json:"releases"`
}
type ReleaseDetails struct {
	FixVersion             string                      `json:"fix_version,omitempty"`
	WillNotFix             bool                        `json:"will_not_fix,omitempty"`
	Severity               string                      `json:"severity,omitempty"`
	Statement              string                      `json:"statement,omitempty"`
	SecurityAdvisory       map[string]SecurityAdvisory `json:"security_advisory,omitempty"`
	ClassificationID       int64                       `json:"classification_id,omitempty"`
	SeverityClassification string                      `json:"severity_classification,omitempty"`
}

type VulnerabilityDetail struct {
	Name                   string             `json:"name,omitempty"`
	FixVersion             string             `json:"fix_version,omitempty"`
	CVE                    string             `json:"cve,omitempty"`
	WillNotFix             bool               `json:"will_not_fix,omitempty"`
	Severity               string             `json:"severity,omitempty"`
	Statement              string             `json:"statement,omitempty"`
	SecurityAdvisory       []SecurityAdvisory `json:"security_advisory,omitempty"`
	ClassificationID       int64              `json:"classification_id,omitempty"`
	SeverityClassification string             `json:"severity_classification,omitempty"`
}

type debianStage struct {
	fn   func() error
	name string
}

var SeverityClassification = map[string]string{
	"<no-dsa>":       "Fix Version: No DSA",
	"<ignored>":      "Fix Version: Ignored",
	"<postponed>":    "Fix Version: Postponed",
	"<undetermined>": "Fix Version: Undetermined",
}

type SecurityAdvisory struct {
	ID          string `json:"id,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Description string `json:"description,omitempty"`
	PublishDate string `json:"publish_date,omitempty"`
}

func NewClient() *DebianSalsa {
	return &DebianSalsa{
		cloneCommand: cloneCmd,
		VulnListDir:  utils.VulnListDir(),
		cveToDSA:     make(map[string][]dsa),
		PackageData:  make(map[string]map[string]CVERelease),
	}
}

func (ctx DebianSalsa) Update() error {
	log.Println("Fetching Debian Salsa data...")
	log.Println("Cloning repository", "git "+cloneCmd)
	args := strings.Split(cloneCmd, " ")
	_, err := exec.Command("git", args...).Output()
	if err != nil {
		return errors.Wrap(err, "failed cloning repository")
	}
	defer os.RemoveAll("security-tracker") // nolint: errcheck
	for _, stage := range []debianStage{
		{ctx.getReleases, "getting releases"},
		{ctx.parseDSAs, "parsing DSAs"},
		{ctx.parseCVEs, "parsing CVEs"},
	} {
		err := stage.fn()
		if err != nil {
			return errors.Wrapf(err, "failed %s", stage.name)
		}
	}
	/*go over all other releases, and if we haven't seen them, add them the same information from sid,
	because it's true for them as well*/
	for _, cveRelMap := range ctx.PackageData {
		for _, relData := range cveRelMap {
			if sidData, isSid := relData.Releases["sid"]; isSid {
				for relName := range ctx.oss {
					if _, seen := relData.Releases[relName]; !seen {
						relData.Releases[relName] = sidData
					}
				}
			}
		}
	}

	log.Println("Saving new data")
	bar := pb.StartNew(len(ctx.PackageData))
	for pkgName, cveRelease := range ctx.PackageData {
		pkgDir := filepath.Join(ctx.VulnListDir, debianDir, pkgName)
		if err := os.MkdirAll(pkgDir, os.ModePerm); err != nil {
			return xerrors.Errorf("failed to create the directory: %w", err)
		}
		for cveID, releases := range cveRelease {
			filePath := filepath.Join(pkgDir, fmt.Sprintf("%s.json", cveID))
			if err := utils.Write(filePath, releases); err != nil {
				return xerrors.Errorf("failed to write Debian CVE details: %w", err)
			}
		}
		bar.Increment()
	}
	bar.Finish()
	return nil
}
func (ctx *DebianSalsa) getReleases() (err error) {
	log.Println("Getting releases")
	// start by getting Debian releases covered by the security tracker
	// these are listed by codenames, so we will collect code names now, and later
	// on get the actual version numbers
	codeToVer := make(map[string]string)
	//oss := make(map[string]int64)
	log.Println("Fetching covered releases page", coveredReleasesURL)
	b, err := utils.FetchURL(coveredReleasesURL, "", 3)
	if err != nil {
		return err
	}
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(b))
	if err != nil {
		return err
	}
	rows := doc.Find("table tbody tr")
	for i := range rows.Nodes {
		row := rows.Eq(i)
		td := row.Find("td")
		// the first line is the header line and has <th> elements rather than <td> elements
		if len(td.Nodes) == 0 {
			continue
		}
		rel := td.Eq(0).Text()
		// ignore backport releases
		if strings.HasSuffix(rel, "-backports") {
			continue
		}
		codeToVer[rel] = ""
	}
	// okay, let's get the version numbers for every release
	codeToVer["sid"] = "unstable" // this is always true
	log.Println("Fetching releases page", releasesURL)
	buf, err := utils.FetchURL(releasesURL, "", 3)
	if err != nil {
		return err
	}
	doc, err = goquery.NewDocumentFromReader(bytes.NewReader(buf))
	if err != nil {
		return err
	}
	rows = doc.Find("#content ul li")
	for i := range rows.Nodes {
		a := rows.Eq(i).Find("a")
		codeName := a.Find("q").Text()
		if i == 0 {
			codeToVer[codeName] = "testing"
		} else {
			// ignore codenames we don't know (because the security tracker
			// doesn't support them)
			if _, ok := codeToVer[codeName]; !ok {
				continue
			}
			matches := releaseRegexp.FindStringSubmatch(a.Text())
			if len(matches) < 2 {
				return errors.Errorf("failed parsing release %s", codeName)
			}
			codeToVer[codeName] = matches[1]
		}
	}

	// force Debian 7 (wheezy) to be in the releases we're covering. The Debian
	// security tracker is not covering it anymore, but we will continue covering
	// it (albeit incompletely, as new vulnerabilities will not be marked as
	// affected for wheezy, although they should) until we inform customers that
	// it has reached end of life (TODO: implement a formal EOL process)
	codeToVer["wheezy"] = "7"
	codeToVer["jessie"] = "8"
	ctx.oss = codeToVer
	return nil
}
func (ctx *DebianSalsa) parseDSAs() error {
	log.Println("Getting advisories")
	for _, tp := range []string{"DSA", "DLA"} {
		dsaFile, err := os.Open("security-tracker/data/" + tp + "/list")
		if err != nil {
			return errors.Wrapf(err, "failed opening %s list", tp)
		}
		var currentDSA dsa
		scanner := bufio.NewScanner(dsaFile)
		for scanner.Scan() {
			line := scanner.Text()
			matches := dsaLine.FindStringSubmatch(line)
			if len(matches) == 4 {
				// this is a DSA line
				// have we finished processing a DSA?
				if currentDSA.name != "" {
					if ctx.cveToDSA == nil {
						ctx.cveToDSA = make(map[string][]dsa)
					}
					for _, cve := range currentDSA.cves {
						ctx.cveToDSA[cve] = append(ctx.cveToDSA[cve], currentDSA)
					}
				}
				currentDSA = dsa{name: matches[2], description: matches[3]}
				currentDSA.date, err = time.Parse("02 Jan 2006", matches[1])
				if err != nil {
					log.Println("Error", err)
					return xerrors.Errorf("failed parsing date:%s %w", matches[1], err)
				}
			} else if currentDSA.name != "" {
				// this is a line about the current DSA
				cveMatches := dsaCVEsLine.FindAllStringSubmatch(line, -1)
				if len(cveMatches) > 0 {
					for _, match := range cveMatches {
						if match[1] != "" {
							currentDSA.cves = append(currentDSA.cves, match[1])
						}
					}
				} else {
					matches := dsaPkgLine.FindStringSubmatch(line)
					if len(matches) == 4 {
						// ignore unsupported releases
						if _, exists := ctx.oss[matches[1]]; !exists {
							continue
						}

						currentDSA.packages = append(currentDSA.packages, pkg{
							release: matches[1],
							name:    matches[2],
							version: matches[3],
						})
					}
				}
			}
		}
		dsaFile.Close() // nolint: errcheck
	}
	return nil
}

func (ctx *DebianSalsa) parseCVEs() error {
	log.Println("Processing CVEs")
	cveFile, err := os.Open("security-tracker/data/CVE/list")
	if err != nil {
		return xerrors.Errorf("failed opening CVE list: %w", err)
	}
	var currentCVE cve
	scanner := bufio.NewScanner(cveFile)
	for scanner.Scan() {
		line := scanner.Text()
		matches := cveLine.FindStringSubmatch(line)
		if len(matches) == 2 {
			if currentCVE.name != "" {
				err = ctx.processCVE(currentCVE)
				if err != nil {
					log.Println("Error", err)
				}
			}
			currentCVE = cve{name: matches[1]}
		} else if currentCVE.name != "" {
			// this is a line about the current CVE
			if notForUsLine.MatchString(line) {
				currentCVE.notForUs = true
				continue
			} else if reservedLine.MatchString(line) {
				currentCVE.reserved = true
				continue
			} else {
				matches := noteLine.FindStringSubmatch(line)
				if len(matches) == 2 {
					currentCVE.notes = append(currentCVE.notes, matches[1])
					continue
				}
				matches = packageLine.FindStringSubmatch(line)
				if len(matches) == 5 {
					currentCVE.packages = append(currentCVE.packages, pkg{
						release:  matches[1],
						name:     matches[2],
						version:  matches[3],
						severity: matches[4],
					})
				}
			}
		}
	}
	cveFile.Close() // nolint: errcheck
	return nil
}

func (ctx *DebianSalsa) processCVE(cve cve) error {
	// ignore NOT-FOR-US vulnerabilities
	if cve.notForUs {
		return nil
	}
	// ignore vulnerabilities that do not have IDs
	if strings.HasSuffix(cve.name, "-XXXX") {
		return nil
	}
	for _, p := range cve.packages {
		// ignore releases not supported by the security tracker
		if p.release != "" {
			if _, exists := ctx.oss[p.release]; !exists {
				continue
			}
		}
		if p.release == "" {
			p.release = "sid"
		}
		if p.version == "<not-affected>" || p.version == "<removed>" {
			continue
		} else if p.version == "<unfixed>" || p.version == "<end-of-life>" {
			// this vulnerability has not been fixed yet
			p.version = ""
		} else if p.version == "<no-dsa>" ||
			p.version == "<ignored>" ||
			p.version == "<postponed>" {
			if p.version == "<ignored>" {
				p.willNotFix = true
			}
			p.severityClassification = SeverityClassification[p.version]
			p.statement = p.severity
			p.version = ""
			p.severity = "negligible"
			p.classification = 1
		} else if p.version == "<undetermined>" {
			// package is _probably_ vulnerable, but the severity is unknown
			p.severityClassification = SeverityClassification[p.version]
			p.statement = p.severity
			p.version = ""
			p.severity = "unknown"
			p.classification = 2
		}
		// remove bug numbers from severity
		p.severity = bugNumber.ReplaceAllString(p.severity, "")
		// by now, severity should be one of "unknown", "negligible",
		// "low", "medium" or "high". If it's anything else, it's probably a note rather than a severity
		if p.severity != "unknown" &&
			p.severity != "unimportant" &&
			p.severity != "negligible" &&
			p.severity != "low" &&
			p.severity != "medium" &&
			p.severity != "high" {
			if p.statement == "" {
				p.statement = p.severity
			}
			p.severity = ""
		}
		// a package may have a vendor statement, but the CVE
		// itself may also have notes, so let's add them too
		// if they exist
		var notes []string
		if p.statement != "" {
			notes = append(notes, p.statement)
		}
		if len(cve.notes) > 0 {
			notes = append(notes, cve.notes...)
		}
		p.statement = strings.Join(notes, "\n")
		seenRelease := false
		// is this CVE part of a security advisory?
		dsas, cveInDSA := ctx.cveToDSA[cve.name]
		if cveInDSA {
			for _, dsa := range dsas {
				for _, dsaPkg := range dsa.packages {
					if dsaPkg.name == p.name {
						if _, exists := ctx.oss[dsaPkg.release]; !exists {
							log.Println("Unknown OS, skipping", dsaPkg.release)
							break
						}
						if dsaPkg.release == p.release {
							seenRelease = true
						}
						if ctx.PackageData[dsaPkg.name] == nil {
							releaseDetails := ReleaseDetails{
								FixVersion: dsaPkg.version,
								Severity:   p.severity,
								Statement:  p.statement,
								SecurityAdvisory: map[string]SecurityAdvisory{dsa.name: {
									PublishDate: dsa.date.String(),
									Description: dsa.description,
								}},
								ClassificationID: p.classification,
							}
							cveRel := CVERelease{Description: p.statement, Releases: map[string]ReleaseDetails{dsaPkg.release: releaseDetails}}
							ctx.PackageData[dsaPkg.name] = map[string]CVERelease{cve.name: cveRel}
						} else {
							if cveRelease, cveInMap := ctx.PackageData[dsaPkg.name][cve.name]; cveInMap {
								if _, isRelInMap := cveRelease.Releases[dsaPkg.release]; !isRelInMap {
									cveRelease.Releases[dsaPkg.release] = ReleaseDetails{
										FixVersion: dsaPkg.version,
										Severity:   p.severity,
										Statement:  p.statement,
										SecurityAdvisory: map[string]SecurityAdvisory{dsa.name: {
											PublishDate: dsa.date.String(),
											Description: dsa.description,
										}},
										ClassificationID: p.classification,
									}
									ctx.PackageData[dsaPkg.name][cve.name] = cveRelease
								}
							} else {
								newRelDetail := ReleaseDetails{
									FixVersion: dsaPkg.version,
									Severity:   p.severity,
									Statement:  p.statement,
									SecurityAdvisory: map[string]SecurityAdvisory{dsa.name: {
										PublishDate: dsa.date.String(),
										Description: dsa.description,
									}},
									ClassificationID: p.classification}
								cveRel := CVERelease{Description: p.statement, Releases: map[string]ReleaseDetails{dsaPkg.release: newRelDetail}}
								ctx.PackageData[dsaPkg.name][cve.name] = cveRel
							}
						}
					}
				}
			}
		}
		if !seenRelease {
			if _, exists := ctx.oss[p.release]; !exists {
				continue
			}
			if ctx.PackageData[p.name] == nil {
				releaseDetails := ReleaseDetails{
					FixVersion:             p.version,
					Severity:               p.severity,
					Statement:              p.statement,
					WillNotFix:             p.willNotFix,
					ClassificationID:       p.classification,
					SeverityClassification: p.severityClassification,
				}
				cveRel := CVERelease{Description: p.statement, Releases: map[string]ReleaseDetails{p.release: releaseDetails}}
				ctx.PackageData[p.name] = map[string]CVERelease{cve.name: cveRel}
			} else {
				if cveRelease, cveInMap := ctx.PackageData[p.name][cve.name]; cveInMap {
					cveRelease.Releases[p.release] = ReleaseDetails{
						FixVersion:             p.version,
						Severity:               p.severity,
						Statement:              p.statement,
						WillNotFix:             p.willNotFix,
						ClassificationID:       p.classification,
						SeverityClassification: p.severityClassification,
					}
					ctx.PackageData[p.name][cve.name] = cveRelease
				} else {
					newRelDetail := ReleaseDetails{
						FixVersion:             p.version,
						Severity:               p.severity,
						Statement:              p.statement,
						WillNotFix:             p.willNotFix,
						ClassificationID:       p.classification,
						SeverityClassification: p.severityClassification}
					cveRel := CVERelease{Description: p.statement, Releases: map[string]ReleaseDetails{p.release: newRelDetail}}
					ctx.PackageData[p.name][cve.name] = cveRel
				}
			}
		}
	}

	return nil
}
