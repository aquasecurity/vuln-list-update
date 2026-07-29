// Package osv fetches Chainguard's OSV v3 security feed, which supersedes the
// deprecated secdb (security.json) feed for Chainguard Images and Wolfi.
//
// The feed publishes one file per advisory - around 800k of them - so this
// updater consumes the tar archive of the whole feed rather than the individual
// record endpoints, and groups the advisories by package before writing them
// out. Grouping keeps the generated tree at roughly one file per package
// instead of one file per advisory.
//
// Feed documentation:
// https://github.com/chainguard-dev/vulnerability-scanner-support/blob/main/docs/osv_v3_feed.md
package osv

import (
	"archive/tar"
	"cmp"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	// tarballURL holds every advisory record in the v3 feed.
	tarballURL = "https://packages.cgr.dev/chainguard/v3/osv/chainguard-osv.tar.gz"

	// advisoryDir is the vuln-list directory the grouped advisories are written to.
	// The feed version is part of the path so that a future feed version can be
	// added alongside this one.
	advisoryDir = "chainguard/v3"

	// ecosystemChainguard covers packages built and distributed by Chainguard.
	ecosystemChainguard = "Chainguard"
	// ecosystemWolfi covers packages from the Wolfi repository. Wolfi packages
	// also get a Chainguard entry with the same version range.
	ecosystemWolfi = "Wolfi"

	defaultRetry   = 3
	defaultTimeout = 30 * time.Minute
)

// supportedEcosystems are the ecosystems written out, keyed by the directory
// name used for each. Any other ecosystem in the feed is ignored.
var supportedEcosystems = map[string]string{
	ecosystemChainguard: "chainguard",
	ecosystemWolfi:      "wolfi",
}

// statusPrecedence orders advisory statuses from the one a consumer most needs
// to know about to the one it least needs, and is used to pick a single status
// when an affected entry carries more than one component. The version range
// already encodes whether the advisory is resolved, so the status is only
// carried through for reporting.
// cf. https://edu.chainguard.dev/chainguard/chainguard-images/staying-secure/security-advisories/how-chainguard-issues/
var statusPrecedence = []string{
	"true_positive_determination",
	"pending_upstream_fix",
	"fix_not_planned",
	"analysis_not_planned",
	"detection",
	"fixed",
	"false_positive_determination",
}

// validPkgName guards against a package name from the feed escaping the output
// directory or producing an unusable file name. APK names are limited to
// alphanumerics and "._+-".
var validPkgName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

type option func(*Updater)

// WithVulnListDir overrides the directory the advisories are written to.
func WithVulnListDir(v string) option {
	return func(u *Updater) { u.vulnListDir = v }
}

// WithAppFs overrides the filesystem, for tests.
func WithAppFs(v afero.Fs) option {
	return func(u *Updater) { u.appFs = v }
}

// WithTarballURL overrides the feed URL, for tests.
func WithTarballURL(v string) option {
	return func(u *Updater) { u.tarballURL = v }
}

// WithRetry overrides how many times a failed download is retried.
func WithRetry(v int) option {
	return func(u *Updater) { u.retry = v }
}

// Updater fetches the Chainguard OSV v3 feed and writes it to vuln-list.
type Updater struct {
	vulnListDir string
	appFs       afero.Fs
	tarballURL  string
	retry       int
	client      *http.Client
}

// NewUpdater returns an Updater for the Chainguard OSV v3 feed.
func NewUpdater(options ...option) *Updater {
	updater := &Updater{
		vulnListDir: utils.VulnListDir(),
		appFs:       afero.NewOsFs(),
		tarballURL:  tarballURL,
		retry:       defaultRetry,
		client:      &http.Client{Timeout: defaultTimeout},
	}
	for _, option := range options {
		option(updater)
	}
	return updater
}

// Update replaces the Chainguard OSV v3 advisories in vuln-list with the
// current contents of the feed.
func (u *Updater) Update() error {
	dir := path.Join(u.vulnListDir, advisoryDir)
	log.Printf("Remove Chainguard OSV v3 directory %s", dir)
	if err := u.appFs.RemoveAll(dir); err != nil {
		return xerrors.Errorf("failed to remove Chainguard OSV v3 directory: %w", err)
	}

	log.Println("Fetching Chainguard OSV v3 data...")
	packages, err := u.fetch()
	if err != nil {
		return xerrors.Errorf("failed to fetch Chainguard OSV v3 data: %w", err)
	}

	log.Printf("Writing %d Chainguard OSV v3 package files...", len(packages))
	return u.save(dir, packages)
}

// packageKey identifies one output file.
type packageKey struct {
	ecosystem string
	name      string
}

// fetch streams the feed tarball and groups the advisories by ecosystem and
// package.
func (u *Updater) fetch() (map[packageKey]*Package, error) {
	var lastErr error
	for attempt := 0; attempt <= u.retry; attempt++ {
		if attempt > 0 {
			wait := time.Duration(attempt*attempt) * time.Second
			log.Printf("Retrying Chainguard OSV v3 download in %s: %s", wait, lastErr)
			time.Sleep(wait)
		}

		packages, err := u.fetchOnce()
		if err == nil {
			return packages, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (u *Updater) fetchOnce() (map[packageKey]*Package, error) {
	resp, err := u.client.Get(u.tarballURL)
	if err != nil {
		return nil, xerrors.Errorf("http get error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, xerrors.Errorf("bad response for %s: status code: %d", u.tarballURL, resp.StatusCode)
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, xerrors.Errorf("gzip reader error: %w", err)
	}
	defer gr.Close()

	packages := make(map[packageKey]*Package)
	var records, skippedNames int
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, xerrors.Errorf("tar read error: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		// The archive also contains the all.json index, which is not an
		// advisory record.
		name := path.Base(hdr.Name)
		if !strings.HasPrefix(name, "CGA-") || !strings.HasSuffix(name, ".json") {
			continue
		}

		var rec record
		if err := json.NewDecoder(tr).Decode(&rec); err != nil {
			return nil, xerrors.Errorf("json decode error (%s): %w", hdr.Name, err)
		}
		records++
		skippedNames += addRecord(packages, rec)
	}

	if records == 0 {
		return nil, xerrors.Errorf("no advisory records found in %s", u.tarballURL)
	}
	if skippedNames > 0 {
		log.Printf("Skipped %d affected entries with an unusable package name", skippedNames)
	}
	log.Printf("Parsed %d Chainguard OSV v3 records into %d package files", records, len(packages))

	for _, p := range packages {
		slices.SortFunc(p.Advisories, func(a, b Advisory) int {
			if c := cmp.Compare(a.ID, b.ID); c != 0 {
				return c
			}
			return cmp.Compare(a.Arch, b.Arch)
		})
	}
	return packages, nil
}

// addRecord splits one advisory record into its per-package advisories and adds
// them to packages. It returns the number of affected entries it had to skip.
func addRecord(packages map[packageKey]*Package, rec record) int {
	var skipped int
	for _, aff := range rec.Affected {
		if _, ok := supportedEcosystems[aff.Package.Ecosystem]; !ok {
			continue
		}
		if !validPkgName.MatchString(aff.Package.Name) {
			skipped++
			continue
		}

		var events []Event
		for _, r := range aff.Ranges {
			events = append(events, r.Events...)
		}

		key := packageKey{
			ecosystem: aff.Package.Ecosystem,
			name:      aff.Package.Name,
		}
		p, ok := packages[key]
		if !ok {
			p = &Package{
				Ecosystem: aff.Package.Ecosystem,
				Name:      aff.Package.Name,
			}
			packages[key] = p
		}
		p.Advisories = append(p.Advisories, Advisory{
			ID:       rec.ID,
			Upstream: rec.Upstream,
			Arch:     archFromPURL(aff.Package.PURL),
			Events:   events,
			Status:   status(aff.EcosystemSpecific.Components),
		})
	}
	return skipped
}

// archFromPURL returns the value of the ?arch= qualifier of a package PURL,
// e.g. "x86_64" for "pkg:apk/chainguard/curl?arch=x86_64".
func archFromPURL(purl string) string {
	_, qualifiers, found := strings.Cut(purl, "?")
	if !found {
		return ""
	}
	for q := range strings.SplitSeq(qualifiers, "&") {
		if arch, ok := strings.CutPrefix(q, "arch="); ok {
			return arch
		}
	}
	return ""
}

// status reduces the components of an affected entry to the single status that
// best describes it. The v3 feed publishes one component per affected entry, so
// this only matters if that ever changes.
func status(components []component) string {
	best := ""
	bestRank := len(statusPrecedence)
	for _, c := range components {
		rank := slices.Index(statusPrecedence, c.LatestEventStatus)
		if rank < 0 {
			// An unknown status is more interesting than a known one, since it
			// cannot be assumed to be resolved.
			if best == "" {
				best = c.LatestEventStatus
			}
			continue
		}
		if rank < bestRank {
			best, bestRank = c.LatestEventStatus, rank
		}
	}
	return best
}

func (u *Updater) save(dir string, packages map[packageKey]*Package) error {
	for key, p := range packages {
		ecosystemDir, ok := supportedEcosystems[key.ecosystem]
		if !ok {
			continue
		}
		filePath := path.Join(dir, ecosystemDir, fmt.Sprintf("%s.json", key.name))
		if err := u.write(filePath, p); err != nil {
			return xerrors.Errorf("failed to write %s: %w", filePath, err)
		}
	}
	return nil
}

// write marshals data to filePath. utils.Write is not used because it writes
// through the os package directly, which the tests cannot intercept.
func (u *Updater) write(filePath string, data any) error {
	if err := u.appFs.MkdirAll(path.Dir(filePath), 0755); err != nil {
		return xerrors.Errorf("mkdir error: %w", err)
	}

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return xerrors.Errorf("JSON marshal error: %w", err)
	}
	return afero.WriteFile(u.appFs, filePath, b, 0644)
}
