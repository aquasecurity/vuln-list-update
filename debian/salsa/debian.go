package salsa

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/aquasecurity/vuln-list-update/git"

	"golang.org/x/xerrors"

	"github.com/cheggaaa/pb"
	"github.com/pkg/errors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	cloneURL  = "https://salsa.debian.org/security-tracker-team/security-tracker.git"
	debianDir = "debian-salsa"
)

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
	VulnListDir    string
	oss            map[string]string
	cveToDSA       map[string][]dsa
	PackageData    map[string]map[string]CVERelease
	cloneDirectory string
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

type DebianReleases struct {
	MajorVersion string `json:"major-version"`
}

func NewClient() *DebianSalsa {
	return &DebianSalsa{
		VulnListDir:    utils.VulnListDir(),
		cveToDSA:       make(map[string][]dsa),
		PackageData:    make(map[string]map[string]CVERelease),
		cloneDirectory: salsaDebianCloneDir(),
	}
}

func (ctx DebianSalsa) Update() error {
	gc := git.Config{}
	log.Println("Fetching Debian Salsa data...")
	log.Println("Cloning repository", cloneURL)

	if _, err := gc.CloneOrPull(cloneURL, ctx.cloneDirectory, "master", true, false); err != nil {
		return xerrors.Errorf("failed to clone or pull: %w", err)
	}
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
	defer os.RemoveAll(ctx.cloneDirectory) // nolint: errcheck

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
	distributionFile := filepath.Join(ctx.cloneDirectory, "static/distributions.json")
	debianRelData, err := os.Open(distributionFile)
	if err != nil {
		return err
	}
	byteValue, _ := ioutil.ReadAll(debianRelData)
	var releases map[string]DebianReleases
	err = json.Unmarshal(byteValue, &releases)
	if err != nil {
		return err
	}
	codeToVer := make(map[string]string)
	for releaseName, value := range releases {
		if releaseName == "bookworm" || releaseName == "trixie" {
			continue
		}
		codeToVer[releaseName] = value.MajorVersion
	}
	codeToVer["sid"] = "unstable"
	ctx.oss = codeToVer
	return nil
}
func (ctx *DebianSalsa) parseDSAs() error {
	log.Println("Getting advisories")
	for _, tp := range []string{"DSA", "DLA"} {
		listPath := filepath.Join(ctx.cloneDirectory, "data", tp, "list")
		dsaFile, err := os.Open(listPath)
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
	cveListPath := filepath.Join(ctx.cloneDirectory, "data/CVE/list")
	cveFile, err := os.Open(cveListPath)
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
						securityAdv := map[string]SecurityAdvisory{dsa.name: {
							PublishDate: dsa.date.String(),
							Description: dsa.description,
						}}
						if ctx.PackageData[dsaPkg.name] == nil {
							releaseDetails := ReleaseDetails{
								SecurityAdvisory: securityAdv,
							}
							cveRel := CVERelease{Description: p.statement, Releases: map[string]ReleaseDetails{dsaPkg.release: releaseDetails}}
							ctx.PackageData[dsaPkg.name] = map[string]CVERelease{cve.name: cveRel}
						} else {
							releaseDetails := ReleaseDetails{
								FixVersion:       dsaPkg.version,
								Severity:         p.severity,
								Statement:        p.statement,
								SecurityAdvisory: securityAdv,
								ClassificationID: p.classification,
							}
							if cveRelease, cveInMap := ctx.PackageData[dsaPkg.name][cve.name]; cveInMap {
								if _, isRelInMap := cveRelease.Releases[dsaPkg.release]; !isRelInMap {
									cveRelease.Releases[dsaPkg.release] = releaseDetails
									ctx.PackageData[dsaPkg.name][cve.name] = cveRelease
								}
							} else {
								cveRel := CVERelease{Description: p.statement, Releases: map[string]ReleaseDetails{dsaPkg.release: releaseDetails}}
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
			releaseDetails := ReleaseDetails{
				FixVersion:             p.version,
				Severity:               p.severity,
				Statement:              p.statement,
				WillNotFix:             p.willNotFix,
				ClassificationID:       p.classification,
				SeverityClassification: p.severityClassification,
			}
			if ctx.PackageData[p.name] == nil {
				cveRel := CVERelease{Releases: map[string]ReleaseDetails{p.release: releaseDetails}}
				ctx.PackageData[p.name] = map[string]CVERelease{cve.name: cveRel}
			} else {
				if cveRelease, cveInMap := ctx.PackageData[p.name][cve.name]; cveInMap {
					cveRelease.Releases[p.release] = releaseDetails
					ctx.PackageData[p.name][cve.name] = cveRelease
				} else {
					cveRel := CVERelease{Description: p.statement, Releases: map[string]ReleaseDetails{p.release: releaseDetails}}
					ctx.PackageData[p.name][cve.name] = cveRel
				}
			}
		}
	}

	return nil
}

func salsaDebianCloneDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, "security-tracker")
	return dir
}
