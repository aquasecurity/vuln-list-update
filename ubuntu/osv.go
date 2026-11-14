package ubuntu

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	osvURL = "https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/all.zip"
	osvDir = "ubuntu-osv"

	// Only UBUNTU-CVE records are read. USN records repeat their fixes, and a USN lists the CVEs
	// of all its packages and releases together, so its fixes cannot be tied to one CVE.
	cveIDPrefix = "UBUNTU-CVE-"
)

// osvEcosystemRe matches "Ubuntu:24.04:LTS" and "Ubuntu:25.10" and captures the release.
// Other ecosystems such as "Ubuntu:Pro:20.04:LTS" or "Ubuntu:Pro:FIPS:22.04:LTS" don't match.
var osvEcosystemRe = regexp.MustCompile(`^Ubuntu:(\d+\.\d+)(:LTS)?$`)

// SourceBinaries maps a source package to the binary packages built from it in one release.
// It is written to ubuntu-osv/<release>/<source>.json.
type SourceBinaries struct {
	Source   string
	Binaries []string
	// BinaryFixedVersions holds fixed versions of binary packages that differ from
	// the fixed version of the source package, keyed by vulnerability ID and binary package.
	BinaryFixedVersions map[string]map[string]string `json:",omitempty"`
	// SourceFixedVersions holds the fixed version of the source package for each vulnerability in BinaryFixedVersions.
	SourceFixedVersions map[string]string `json:",omitempty"`
}

// ubuntuOSV contains only the fields of an OSV record that are needed to build SourceBinaries.
type ubuntuOSV struct {
	ID        string `json:"id"`
	Withdrawn string `json:"withdrawn"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
		EcosystemSpecific struct {
			Binaries []struct {
				Name    string `json:"binary_name"`
				Version string `json:"binary_version"`
			} `json:"binaries"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

type releaseSource struct {
	release string
	source  string
}

// sourceBinaries collects SourceBinaries across records. Binaries are kept in a set,
// because every record of the source package repeats them.
type sourceBinaries struct {
	binaries            map[string]struct{}
	binaryFixedVersions map[string]map[string]string
	sourceFixedVersions map[string]string
}

func (s *sourceBinaries) build(source string) SourceBinaries {
	binaries := make([]string, 0, len(s.binaries))
	for name := range s.binaries {
		binaries = append(binaries, name)
	}
	slices.Sort(binaries)
	return SourceBinaries{
		Source:              source,
		Binaries:            binaries,
		BinaryFixedVersions: s.binaryFixedVersions,
		SourceFixedVersions: s.sourceFixedVersions,
	}
}

type OSVUpdater struct {
	url string
	dir string
}

type OSVOption func(*OSVUpdater)

func WithOSVURL(url string) OSVOption {
	return func(u *OSVUpdater) {
		u.url = url
	}
}

// WithOSVDir sets the vuln-list directory. The data is written to its ubuntu-osv subdirectory.
func WithOSVDir(dir string) OSVOption {
	return func(u *OSVUpdater) {
		u.dir = dir
	}
}

func NewOSVUpdater(opts ...OSVOption) OSVUpdater {
	u := OSVUpdater{
		url: osvURL,
		dir: utils.VulnListDir(),
	}
	for _, opt := range opts {
		opt(&u)
	}
	return u
}

func (u OSVUpdater) Update() error {
	ctx := context.Background()

	log.Printf("[Ubuntu OSV] Downloading %s", u.url)
	archive, err := u.download(ctx)
	if err != nil {
		return xerrors.Errorf("failed to download %s: %w", u.url, err)
	}

	log.Print("[Ubuntu OSV] Parsing the archive")
	sources, err := parseOSVArchive(archive)
	// The archive takes about 800 MB, so it is removed before writing the files
	if rerr := os.Remove(archive); rerr != nil {
		log.Printf("[Ubuntu OSV] Failed to remove %s: %s", archive, rerr)
	}
	if err != nil {
		return xerrors.Errorf("failed to parse %s: %w", u.url, err)
	}

	// Remove the existing directory to delete data that has been removed from the source
	dir := filepath.Join(u.dir, osvDir)
	log.Printf("[Ubuntu OSV] Removing %s directory", dir)
	if err = os.RemoveAll(dir); err != nil {
		return xerrors.Errorf("failed to remove %s directory: %w", dir, err)
	}

	log.Printf("[Ubuntu OSV] Writing %d files", len(sources))
	for key, sb := range sources {
		filePath := filepath.Join(dir, key.release, fmt.Sprintf("%s.json", key.source))
		if err = utils.Write(filePath, sb.build(key.source)); err != nil {
			return xerrors.Errorf("failed to write %s: %w", filePath, err)
		}
	}
	return nil
}

// download saves the archive to a temporary file, since reading zip entries requires random access.
func (u OSVUpdater) download(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.url, nil)
	if err != nil {
		return "", xerrors.Errorf("failed to build a request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", xerrors.Errorf("request error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", xerrors.Errorf("bad response code: %d", resp.StatusCode)
	}

	f, err := os.CreateTemp("", "vuln-list-update-ubuntu-osv-*.zip")
	if err != nil {
		return "", xerrors.Errorf("failed to create a temp file: %w", err)
	}
	_, err = io.Copy(f, resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", xerrors.Errorf("failed to save the archive: %w", err)
	}
	return f.Name(), nil
}

// parseOSVArchive reads the OSV records of the archive one at a time.
func parseOSVArchive(archive string) (map[releaseSource]*sourceBinaries, error) {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return nil, xerrors.Errorf("failed to open the archive: %w", err)
	}
	defer r.Close()

	sources := make(map[releaseSource]*sourceBinaries)
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rec, err := decodeOSVEntry(f)
		if err != nil {
			return nil, xerrors.Errorf("failed to decode %s: %w", f.Name, err)
		}
		if !strings.HasPrefix(rec.ID, cveIDPrefix) || rec.Withdrawn != "" {
			continue
		}
		addOSVRecord(sources, rec)
	}
	return sources, nil
}

func decodeOSVEntry(f *zip.File) (ubuntuOSV, error) {
	rc, err := f.Open()
	if err != nil {
		return ubuntuOSV{}, xerrors.Errorf("failed to open: %w", err)
	}
	defer rc.Close()

	var rec ubuntuOSV
	if err = json.NewDecoder(rc).Decode(&rec); err != nil {
		return ubuntuOSV{}, xerrors.Errorf("json decode error: %w", err)
	}
	return rec, nil
}

// isKernelSource reports whether the source package is a kernel ("linux", "linux-aws", "linux-hwe-6.8" and so on).
// Kernels have hundreds of ABI-versioned binaries and would take most of the output.
func isKernelSource(name string) bool {
	return name == "linux" || strings.HasPrefix(name, "linux-")
}

func addOSVRecord(sources map[releaseSource]*sourceBinaries, rec ubuntuOSV) {
	vulnID := strings.TrimPrefix(rec.ID, "UBUNTU-")

	// A record may list the same source package in several affected entries,
	// so binaries and fixed versions are grouped before comparing them.
	type group struct {
		binaries map[string]string // binary package => binary version
		fixed    []string
	}
	groups := make(map[releaseSource]*group)
	for _, a := range rec.Affected {
		m := osvEcosystemRe.FindStringSubmatch(a.Package.Ecosystem)
		if m == nil || a.Package.Name == "" || isKernelSource(a.Package.Name) {
			continue
		}
		key := releaseSource{
			release: m[1],
			source:  a.Package.Name,
		}
		g, ok := groups[key]
		if !ok {
			g = &group{binaries: make(map[string]string)}
			groups[key] = g
		}
		for _, b := range a.EcosystemSpecific.Binaries {
			if b.Name == "" {
				continue
			}
			g.binaries[b.Name] = b.Version
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" && !slices.Contains(g.fixed, e.Fixed) {
					g.fixed = append(g.fixed, e.Fixed)
				}
			}
		}
	}

	for key, g := range groups {
		// Skip affected entries without binaries, since there is nothing to map
		if len(g.binaries) == 0 {
			continue
		}
		sb, ok := sources[key]
		if !ok {
			sb = &sourceBinaries{binaries: make(map[string]struct{})}
			sources[key] = sb
		}
		for name := range g.binaries {
			sb.binaries[name] = struct{}{}
		}

		switch {
		case len(g.fixed) == 0:
			continue
		case len(g.fixed) > 1:
			log.Printf("[Ubuntu OSV] %s has several fixed versions for %s in %s: %s, skipping binary fixed versions",
				rec.ID, key.source, key.release, strings.Join(g.fixed, ", "))
			continue
		}

		for name, version := range g.binaries {
			if version == "" || version == g.fixed[0] {
				continue
			}
			if sb.binaryFixedVersions == nil {
				sb.binaryFixedVersions = make(map[string]map[string]string)
				sb.sourceFixedVersions = make(map[string]string)
			}
			if sb.binaryFixedVersions[vulnID] == nil {
				sb.binaryFixedVersions[vulnID] = make(map[string]string)
				sb.sourceFixedVersions[vulnID] = g.fixed[0]
			}
			sb.binaryFixedVersions[vulnID][name] = version
		}
	}
}
