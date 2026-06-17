package alinux

import (
	"encoding/json"
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
	csafAdvisoryBaseURL = "https://mirrors.aliyun.com/alinux/cve/data/CSAF/advisories/"
	csafVEXBaseURL      = "https://mirrors.aliyun.com/alinux/cve/data/CSAF/vex/"
	alinuxCSAFVEXDir    = "alinux-csaf-vex"
)

var (
	// advisoryFileRe matches advisory filenames like "alinux2-sa-2019_0001.json"
	advisoryFileRe = regexp.MustCompile(`href="(alinux\d+-sa-\d+_\d+\.json)"`)
	// vexFileRe matches VEX filenames like "CVE-2024-0567.json"
	vexFileRe = regexp.MustCompile(`href="(CVE-\d+-\d+\.json)"`)
	// productVersionRe extracts major version from product names like "Alinux 2.1903", "Alinux 3.2104", "Alinux 4"
	productVersionRe = regexp.MustCompile(`(?i)Alinux\s+(\d+)`)
	// advisoryVersionRe extracts major version from advisory filenames like "alinux2-sa-..."
	advisoryVersionRe = regexp.MustCompile(`^alinux(\d+)-`)
)

// CSAFConfig holds configuration for the Alinux CSAF updater
type CSAFConfig struct {
	vulnListDir string
	retry       int
}

type csafOption func(*CSAFConfig)

// WithCSAFVulnListDir sets the vuln-list directory for testing
func WithCSAFVulnListDir(dir string) csafOption {
	return func(c *CSAFConfig) {
		c.vulnListDir = dir
	}
}

// NewCSAFConfig creates a new CSAFConfig
func NewCSAFConfig(opts ...csafOption) *CSAFConfig {
	config := &CSAFConfig{
		vulnListDir: utils.VulnListDir(),
		retry:       retry,
	}
	for _, opt := range opts {
		opt(config)
	}
	return config
}

// Update fetches and processes both CSAF advisories and VEX data
func (c *CSAFConfig) Update() error {
	log.Println("Fetching Alibaba Cloud Linux CSAF advisories...")
	if err := c.updateAdvisories(); err != nil {
		return xerrors.Errorf("failed to update CSAF advisories: %w", err)
	}

	log.Println("Fetching Alibaba Cloud Linux CSAF VEX data...")
	if err := c.updateVEX(); err != nil {
		return xerrors.Errorf("failed to update CSAF VEX: %w", err)
	}

	return nil
}

// updateAdvisories fetches all CSAF advisory files and converts them to ALSA format
func (c *CSAFConfig) updateAdvisories() error {
	// Fetch the directory listing to get all advisory file names
	fileNames, err := fetchFileList(csafAdvisoryBaseURL, advisoryFileRe)
	if err != nil {
		return xerrors.Errorf("failed to fetch advisory file list: %w", err)
	}
	log.Printf("Found %d CSAF advisory files\n", len(fileNames))

	// Group files by version based on filename prefix
	versionFiles := map[string][]string{}
	for _, name := range fileNames {
		m := advisoryVersionRe.FindStringSubmatch(name)
		if len(m) != 2 {
			log.Printf("Skipping unrecognized advisory file: %s\n", name)
			continue
		}
		ver := m[1]
		versionFiles[ver] = append(versionFiles[ver], name)
	}

	// Process each version
	for ver, files := range versionFiles {
		log.Printf("Processing Alinux %s CSAF advisories (%d files)...\n", ver, len(files))
		dir := filepath.Join(c.vulnListDir, alinuxDir, ver)
		if err := os.RemoveAll(dir); err != nil {
			return xerrors.Errorf("unable to remove directory: %w", err)
		}
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return xerrors.Errorf("failed to mkdir: %w", err)
		}

		bar := pb.StartNew(len(files))
		for _, fileName := range files {
			advisories, err := c.fetchAndParseCSAFAdvisory(csafAdvisoryBaseURL + fileName)
			if err != nil {
				log.Printf("Warning: failed to process %s: %v\n", fileName, err)
				bar.Increment()
				continue
			}
			for _, adv := range advisories {
				filePath := filepath.Join(dir, fmt.Sprintf("%s.json", adv.ID))
				if err := utils.Write(filePath, adv); err != nil {
					return xerrors.Errorf("failed to write advisory %s: %w", adv.ID, err)
				}
			}
			bar.Increment()
		}
		bar.Finish()
	}

	return nil
}

// updateVEX fetches all CSAF VEX files and stores them
func (c *CSAFConfig) updateVEX() error {
	// Fetch the directory listing to get all VEX file names
	fileNames, err := fetchFileList(csafVEXBaseURL, vexFileRe)
	if err != nil {
		return xerrors.Errorf("failed to fetch VEX file list: %w", err)
	}
	log.Printf("Found %d CSAF VEX files\n", len(fileNames))

	vexDir := filepath.Join(c.vulnListDir, alinuxCSAFVEXDir)
	if err := os.RemoveAll(vexDir); err != nil {
		return xerrors.Errorf("unable to remove VEX directory: %w", err)
	}

	bar := pb.StartNew(len(fileNames))
	for _, fileName := range fileNames {
		cveID := strings.TrimSuffix(fileName, ".json")
		url := csafVEXBaseURL + fileName

		data, err := utils.FetchURL(url, "", retry)
		if err != nil {
			log.Printf("Warning: failed to fetch VEX %s: %v\n", fileName, err)
			bar.Increment()
			continue
		}

		// Validate JSON
		var doc CSAFDocument
		if err := json.Unmarshal(data, &doc); err != nil {
			log.Printf("Warning: failed to parse VEX %s: %v\n", fileName, err)
			bar.Increment()
			continue
		}

		// Store using CVE-per-year directory structure
		if err := utils.SaveCVEPerYear(vexDir, cveID, doc); err != nil {
			return xerrors.Errorf("failed to save VEX %s: %w", cveID, err)
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}

// fetchAndParseCSAFAdvisory downloads a CSAF advisory and converts it to ALSA format
func (c *CSAFConfig) fetchAndParseCSAFAdvisory(url string) ([]ALSA, error) {
	data, err := utils.FetchURL(url, "", c.retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch %s: %w", url, err)
	}

	var doc CSAFDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, xerrors.Errorf("failed to parse CSAF advisory: %w", err)
	}

	return convertCSAFToALSA(doc)
}

// convertCSAFToALSA converts a CSAF advisory document to ALSA format
func convertCSAFToALSA(doc CSAFDocument) ([]ALSA, error) {
	advisoryID := doc.Document.Tracking.ID
	severity := doc.Document.AggregateSeverity.Text

	// Extract description from notes
	var description string
	for _, note := range doc.Document.Notes {
		if note.Category == "description" {
			description = note.Text
			break
		}
	}

	// Build a map of product_id -> relationship for quick lookup
	relMap := buildRelationshipMap(doc.ProductTree.Relationships)

	// Process each vulnerability
	for _, vuln := range doc.Vulnerabilities {
		cveID := vuln.CVE
		if cveID == "" {
			continue
		}

		// Extract CVSS3 score string
		var cvss3 string
		if len(vuln.Scores) > 0 {
			cvss3 = vuln.Scores[0].CvssV3.VectorString
		}

		// Extract threat severity (per-CVE)
		var impact string
		for _, t := range vuln.Threats {
			if t.Category == "impact" {
				impact = t.Details
				break
			}
		}

		// Extract CVE description
		var cveDescription string
		for _, note := range vuln.Notes {
			if note.Category == "description" {
				cveDescription = note.Text
				break
			}
		}

		// Extract packages from fixed product_ids
		// Product IDs are in format "Platform:NEVRA" (e.g., "Alinux 2.1903:keepalived-1.3.5-8.3.al7.x86_64")
		packages := extractPackagesFromFixed(vuln.ProductStatus.Fixed, relMap)

		refs := []CveRef{{
			ID:     cveID,
			Href:   fmt.Sprintf("https://alas.aliyuncs.com/cves/detail/%s", cveID),
			Cvss3:  cvss3,
			Impact: impact,
		}}

		if len(packages) == 0 {
			continue
		}

		// Use the CVE-level description if available, otherwise use advisory-level
		desc := cveDescription
		if desc == "" {
			desc = description
		}

		alsa := ALSA{
			ID:          advisoryID,
			Title:       doc.Document.Title,
			Severity:    severity,
			Description: desc,
			Issued:      DateJSON{Date: doc.Document.Tracking.InitialReleaseDate},
			Updated:     DateJSON{Date: doc.Document.Tracking.CurrentReleaseDate},
			Packages:    packages,
			CveIDs:      []string{cveID},
			References:  refs,
		}

		return []ALSA{alsa}, nil
	}

	// If multiple CVEs, create a single advisory with all CVEs
	if len(doc.Vulnerabilities) > 1 {
		var cveIDs []string
		var refs []CveRef
		var allPackages []Package

		for _, vuln := range doc.Vulnerabilities {
			if vuln.CVE == "" {
				continue
			}
			cveIDs = append(cveIDs, vuln.CVE)

			var cvss3, impact string
			if len(vuln.Scores) > 0 {
				cvss3 = vuln.Scores[0].CvssV3.VectorString
			}
			for _, t := range vuln.Threats {
				if t.Category == "impact" {
					impact = t.Details
					break
				}
			}

			refs = append(refs, CveRef{
				ID:     vuln.CVE,
				Href:   fmt.Sprintf("https://alas.aliyuncs.com/cves/detail/%s", vuln.CVE),
				Cvss3:  cvss3,
				Impact: impact,
			})

			pkgs := extractPackagesFromFixed(vuln.ProductStatus.Fixed, relMap)
			allPackages = append(allPackages, pkgs...)
		}

		allPackages = deduplicatePackages(allPackages)

		if len(cveIDs) > 0 && len(allPackages) > 0 {
			alsa := ALSA{
				ID:          advisoryID,
				Title:       doc.Document.Title,
				Severity:    severity,
				Description: description,
				Issued:      DateJSON{Date: doc.Document.Tracking.InitialReleaseDate},
				Updated:     DateJSON{Date: doc.Document.Tracking.CurrentReleaseDate},
				Packages:    allPackages,
				CveIDs:      cveIDs,
				References:  refs,
			}
			return []ALSA{alsa}, nil
		}
	}

	return nil, nil
}

// buildRelationshipMap builds a lookup map from product_id to relationship
func buildRelationshipMap(rels []CSAFRelationship) map[string]CSAFRelationship {
	m := make(map[string]CSAFRelationship, len(rels))
	for _, rel := range rels {
		m[rel.FullProductName.ProductID] = rel
	}
	return m
}

// extractPackagesFromFixed extracts package info from fixed product IDs
func extractPackagesFromFixed(fixedIDs []string, relMap map[string]CSAFRelationship) []Package {
	seen := map[string]bool{}
	var packages []Package

	for _, productID := range fixedIDs {
		rel, ok := relMap[productID]
		if !ok {
			// Try to parse directly from the product ID format "Platform:NEVRA"
			parts := strings.SplitN(productID, ":", 2)
			if len(parts) != 2 {
				continue
			}
			rel = CSAFRelationship{
				ProductReference:          parts[1],
				RelatesToProductReference: parts[0],
			}
		}

		nevra := rel.ProductReference
		name, epoch, version, release, arch, err := parseNEVRA(nevra)
		if err != nil {
			continue
		}

		// Skip source and debug packages
		if arch == "src" {
			continue
		}
		if strings.Contains(name, "-debuginfo") || strings.Contains(name, "-debugsource") {
			continue
		}

		// Deduplicate by package name (different arches have same version)
		key := fmt.Sprintf("%s-%s-%s-%s", name, epoch, version, release)
		if seen[key] {
			continue
		}
		seen[key] = true

		packages = append(packages, Package{
			Name:    name,
			Epoch:   epoch,
			Version: version,
			Release: release,
		})
	}

	return packages
}

// parseNEVRA parses an RPM NEVRA string: name-[epoch:]version-release.arch
func parseNEVRA(nevra string) (name, epoch, version, release, arch string, err error) {
	// Split arch: last '.' separates arch
	lastDot := strings.LastIndex(nevra, ".")
	if lastDot < 0 {
		return "", "", "", "", "", fmt.Errorf("invalid NEVRA: no arch separator: %s", nevra)
	}
	arch = nevra[lastDot+1:]
	rest := nevra[:lastDot]

	// Split release: last '-' separates release
	lastDash := strings.LastIndex(rest, "-")
	if lastDash < 0 {
		return "", "", "", "", "", fmt.Errorf("invalid NEVRA: no release separator: %s", nevra)
	}
	release = rest[lastDash+1:]
	rest = rest[:lastDash]

	// Split version: last '-' separates version from name
	lastDash = strings.LastIndex(rest, "-")
	if lastDash < 0 {
		return "", "", "", "", "", fmt.Errorf("invalid NEVRA: no version separator: %s", nevra)
	}
	version = rest[lastDash+1:]
	name = rest[:lastDash]

	// Check for epoch in version (epoch:version)
	epoch = "0"
	if i := strings.Index(version, ":"); i >= 0 {
		epoch = version[:i]
		version = version[i+1:]
	}

	return
}

// deduplicatePackages removes duplicate packages by name+version+release
func deduplicatePackages(pkgs []Package) []Package {
	seen := map[string]bool{}
	var result []Package
	for _, pkg := range pkgs {
		key := fmt.Sprintf("%s-%s-%s-%s", pkg.Name, pkg.Epoch, pkg.Version, pkg.Release)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, pkg)
	}
	return result
}

// fetchFileList fetches an HTML directory listing and extracts file names matching the pattern
func fetchFileList(baseURL string, pattern *regexp.Regexp) ([]string, error) {
	resp, err := http.Get(baseURL)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch directory listing: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, xerrors.Errorf("HTTP error fetching directory listing: status %d", resp.StatusCode)
	}

	// Read full body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, xerrors.Errorf("failed to read response body: %w", err)
	}

	matches := pattern.FindAllStringSubmatch(string(body), -1)
	var fileNames []string
	for _, m := range matches {
		if len(m) == 2 {
			fileNames = append(fileNames, m[1])
		}
	}

	return fileNames, nil
}
