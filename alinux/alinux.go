package alinux

import (
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	retry    = 3
	alinuxDir = "alinux"
)

var (
	ovalURLs = map[string]string{
		"2": "https://mirrors.aliyun.com/alinux/cve/data/OVAL/alinux-2.1903.oval.xml",
		"3": "https://mirrors.aliyun.com/alinux/cve/data/OVAL/alinux-3.2104.oval.xml",
		"4": "https://mirrors.aliyun.com/alinux/cve/data/OVAL/alinux-4.oval.xml",
	}

	// rpmVerRe parses "package_name is earlier than epoch:version-release" from OVAL test comments
	rpmVerRe = regexp.MustCompile(`^(\S+)\s+is earlier than\s+(.+)$`)
)

// Config holds configuration for the Alinux updater
type Config struct {
	ovalURLs    map[string]string
	vulnListDir string
}

type option func(*Config)

// With sets internal values for testing
func With(ovalURLs map[string]string, vulnListDir string) option {
	return func(c *Config) {
		c.ovalURLs = ovalURLs
		c.vulnListDir = vulnListDir
	}
}

// NewConfig creates a new Config
func NewConfig(opts ...option) *Config {
	config := &Config{
		ovalURLs:    ovalURLs,
		vulnListDir: utils.VulnListDir(),
	}
	for _, opt := range opts {
		opt(config)
	}
	return config
}

// Update fetches and parses OVAL data for all Alinux versions
func (c *Config) Update() error {
	for version, url := range c.ovalURLs {
		log.Printf("Fetching security advisories of Alibaba Cloud Linux %s...\n", version)
		if err := c.update(version, url); err != nil {
			return xerrors.Errorf("failed to update security advisories of Alibaba Cloud Linux %s: %w", version, err)
		}
	}
	return nil
}

func (c *Config) update(version, url string) error {
	dir := filepath.Join(c.vulnListDir, alinuxDir, version)
	if err := os.RemoveAll(dir); err != nil {
		return xerrors.Errorf("unable to remove alinux directory: %w", err)
	}
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}

	advisories, err := fetchOVAL(url)
	if err != nil {
		return xerrors.Errorf("failed to fetch OVAL data: %w", err)
	}

	bar := pb.StartNew(len(advisories))
	for _, adv := range advisories {
		filePath := filepath.Join(dir, fmt.Sprintf("%s.json", adv.ID))
		if err := utils.Write(filePath, adv); err != nil {
			return xerrors.Errorf("failed to write Alinux advisory: %w", err)
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}

func fetchOVAL(url string) ([]ALSA, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch OVAL XML: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, xerrors.Errorf("failed to fetch OVAL XML: status %d", resp.StatusCode)
	}

	return parseOVAL(resp.Body)
}

func parseOVAL(r io.Reader) ([]ALSA, error) {
	var ovalDefs OvalDefinitions
	if err := xml.NewDecoder(r).Decode(&ovalDefs); err != nil {
		return nil, xerrors.Errorf("failed to decode OVAL XML: %w", err)
	}

	// Build lookup maps for tests, objects, and states
	testMap := make(map[string]RPMInfoTest)
	for _, t := range ovalDefs.Tests.RPMInfoTests {
		testMap[t.ID] = t
	}
	objectMap := make(map[string]RPMInfoObject)
	for _, o := range ovalDefs.Objects.RPMInfoObjects {
		objectMap[o.ID] = o
	}
	stateMap := make(map[string]RPMInfoState)
	for _, s := range ovalDefs.States.RPMInfoStates {
		stateMap[s.ID] = s
	}

	var advisories []ALSA
	for _, def := range ovalDefs.Definitions {
		if def.Class != "patch" {
			continue
		}

		adv := convertDefinition(def, testMap, objectMap, stateMap)
		if adv.ID == "" || len(adv.CveIDs) == 0 {
			continue
		}
		advisories = append(advisories, adv)
	}

	return advisories, nil
}

func convertDefinition(def Definition, testMap map[string]RPMInfoTest,
	objectMap map[string]RPMInfoObject, stateMap map[string]RPMInfoState) ALSA {

	meta := def.Metadata

	// Extract advisory ID from reference
	advisoryID := meta.Reference.RefID

	// Extract CVE IDs
	var cveIDs []string
	var refs []CveRef
	for _, cve := range meta.Advisory.Cves {
		cveIDs = append(cveIDs, cve.CveID)
		refs = append(refs, CveRef{
			ID:     cve.CveID,
			Href:   cve.Href,
			Cvss3:  cve.Cvss3,
			Impact: cve.Impact,
		})
	}

	// Extract packages from criteria
	packages := extractPackages(def.Criteria, testMap, objectMap, stateMap)

	return ALSA{
		ID:          advisoryID,
		Title:       meta.Title,
		Severity:    meta.Advisory.Severity,
		Description: meta.Desc,
		Issued:      DateJSON{Date: meta.Advisory.Issued.Date},
		Updated:     DateJSON{Date: meta.Advisory.Updated.Date},
		Packages:    packages,
		CveIDs:      cveIDs,
		References:  refs,
	}
}

func extractPackages(criteria Criteria, testMap map[string]RPMInfoTest,
	objectMap map[string]RPMInfoObject, stateMap map[string]RPMInfoState) []Package {

	var packages []Package

	for _, criterion := range criteria.Criterions {
		pkg := extractPackageFromTest(criterion.TestRef, testMap, objectMap, stateMap)
		if pkg != nil {
			packages = append(packages, *pkg)
		}
	}

	for _, subCriteria := range criteria.Criterias {
		packages = append(packages, extractPackages(subCriteria, testMap, objectMap, stateMap)...)
	}

	return packages
}

func extractPackageFromTest(testRef string, testMap map[string]RPMInfoTest,
	objectMap map[string]RPMInfoObject, stateMap map[string]RPMInfoState) *Package {

	test, ok := testMap[testRef]
	if !ok {
		return nil
	}

	obj, ok := objectMap[test.ObjectRef.Ref]
	if !ok {
		return nil
	}

	state, ok := stateMap[test.StateRef.Ref]
	if !ok {
		return nil
	}

	pkgName := obj.Name
	evr := state.EVR.Value

	epoch, version, release := parseEVR(evr)

	return &Package{
		Name:    pkgName,
		Epoch:   epoch,
		Version: version,
		Release: release,
	}
}

// parseEVR parses epoch:version-release string
// Examples: "0:3.11.13-4.0.1.al8", "1:11-openjdk-11.0.16.0.8-1.al8"
func parseEVR(evr string) (epoch, version, release string) {
	epoch = "0"

	// Split epoch
	parts := strings.SplitN(evr, ":", 2)
	if len(parts) == 2 {
		epoch = parts[0]
		evr = parts[1]
	}

	// Split version-release
	lastDash := strings.LastIndex(evr, "-")
	if lastDash < 0 {
		version = evr
		return
	}
	version = evr[:lastDash]
	release = evr[lastDash+1:]
	return
}
