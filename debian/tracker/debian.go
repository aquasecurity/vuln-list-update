package tracker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	debianDir          = "debian"
	securityTrackerURL = "https://salsa.debian.org/security-tracker-team/security-tracker/-/archive/master/security-tracker-master.tar.gz//security-tracker-master"
	packagesURL        = "https://ftp.debian.org/debian/dists/%s/%s/binary-amd64/Packages.gz"
)

type Bug struct {
	Header      *Header
	Annotations []*Annotation
}

type listParser interface {
	ParseHeader(string) *Header
	Dir() string
}

type options struct {
	trackerURL  string
	packagesURL string
	vulnListDir string
}

type option func(*options)

func WithTrackerURL(url string) option {
	return func(opts *options) {
		opts.trackerURL = url
	}
}

func WithPackagesURL(url string) option {
	return func(opts *options) {
		opts.packagesURL = url
	}
}

func WithVulnListDir(dir string) option {
	return func(opts *options) {
		opts.vulnListDir = dir
	}
}

type Client struct {
	*options
	parsers       []listParser
	annDispatcher annotationDispatcher
}

func NewClient(opts ...option) Client {
	o := &options{
		trackerURL:  securityTrackerURL,
		packagesURL: packagesURL,
		vulnListDir: utils.VulnListDir(),
	}

	for _, opt := range opts {
		opt(o)
	}

	return Client{
		options:       o,
		parsers:       []listParser{cveList{}, dlaList{}, dsaList{}},
		annDispatcher: newAnnotationDispatcher(),
	}
}

func (c Client) Update() error {
	ctx := context.Background()

	log.Println("Removing old Debian data...")
	if err := os.RemoveAll(filepath.Join(c.vulnListDir, debianDir)); err != nil {
		return xerrors.Errorf("failed to remove Debian dir: %w", err)
	}

	log.Println("Fetching Debian data...")
	tmpDir, err := utils.DownloadToTempDir(ctx, c.trackerURL)
	if err != nil {
		return xerrors.Errorf("failed to retrieve Debian Security Tracker: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	for _, p := range c.parsers {
		list := filepath.Join(tmpDir, "data", p.Dir(), "list")
		bugs, err := c.parseList(p, list)
		if err != nil {
			return xerrors.Errorf("debian parse error: %w", err)
		}

		if err = c.update(p.Dir(), bugs); err != nil {
			return xerrors.Errorf("debian update error: %w", err)
		}
	}

	log.Println("Parsing distributions.json...")
	dists, err := c.parseDistributions(tmpDir)
	if err != nil {
		return xerrors.Errorf("failed to update distributions: %w", err)
	}

	distributionJSON := filepath.Join(c.vulnListDir, debianDir, "distributions.json")
	if err = utils.Write(distributionJSON, dists); err != nil {
		return xerrors.Errorf("unable to write %s: %w", distributionJSON, err)
	}

	err = c.updatePackages(ctx, dists)
	if err != nil {
		return xerrors.Errorf("unable to fetch Packages: %w", err)
	}

	return nil
}

func (c Client) update(dirname string, bugs []Bug) error {
	// Save all JSON files
	log.Printf("Saving Debian %s data...", dirname)
	bar := pb.StartNew(len(bugs))
	for _, bug := range bugs {
		fileName := fmt.Sprintf("%s.json", bug.Header.ID)
		filePath := filepath.Join(c.vulnListDir, debianDir, dirname, fileName)
		if err := utils.Write(filePath, bug); err != nil {
			return xerrors.Errorf("debian: write error (%s): %w", filePath, err)
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}

// ref. https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/50ca55fb66ec7592f9bc1053a11dbf0bd50ee425/lib/python/sectracker/parsers.py#L198
func (c Client) parseList(parser listParser, filename string) ([]Bug, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, xerrors.Errorf("unable to open %s: %w", filename, err)
	}

	var (
		bugs   []Bug
		anns   []*Annotation
		header *Header
		lineno int
	)

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		lineno += 1

		switch {
		case line == "":
			continue
		case line[0] == ' ' || line[0] == '\t':
			if header == nil {
				log.Printf("header expected: %s", line)
				continue
			}

			ann := c.annDispatcher.parseAnnotation(line, lineno)
			if ann != nil {
				anns = append(anns, ann)
			}
		default:
			if header != nil {
				if shouldStore(anns) {
					bugs = append(bugs, Bug{
						Header:      header,
						Annotations: anns,
					})
				}
				header = nil
				anns = []*Annotation{}
			}
			header = parser.ParseHeader(line)
			if header == nil {
				log.Printf("malformed header: %s", line)
				continue
			}
			header.Line = lineno
		}
	}

	if err = s.Err(); err != nil {
		return nil, xerrors.Errorf("scan error: %w", err)
	}

	if header != nil && shouldStore(anns) {
		bugs = append(bugs, Bug{
			Header:      header,
			Annotations: anns,
		})
	}

	return bugs, nil
}

type Distribution struct {
	MajorVersion string `json:"major-version"`
	Support      string `json:"support"`
	Contact      string `json:"contact"`
}

func (c Client) parseDistributions(dir string) (map[string]Distribution, error) {
	filename := filepath.Join(dir, "static", "distributions.json")
	f, err := os.Open(filename)
	if err != nil {
		return nil, xerrors.Errorf("unable to open %s: %w", filename, err)
	}

	// For schema validation
	dists := map[string]Distribution{}
	if err = json.NewDecoder(f).Decode(&dists); err != nil {
		return nil, xerrors.Errorf("json error: %w", err)
	}

	return dists, nil
}

func shouldStore(anns []*Annotation) bool {
	for _, ann := range anns {
		if ann.Type == "RESERVED" || ann.Type == "REJECTED" || ann.Type == "NOT-FOR-US" {
			return false
		}
	}
	return true
}

func (c Client) updatePackages(ctx context.Context, dists map[string]Distribution) error {
	// Some codes don't have Packages in the repository
	codes, err := supportedCodes(dists)
	if err != nil {
		return xerrors.Errorf("code error: %w", err)
	}

	for _, code := range codes {
		for _, r := range []string{"main", "contrib"} {
			log.Printf("Updating Packages %s/%s", code, r)
			url := fmt.Sprintf(c.packagesURL, code, r)
			headers, err := c.fetchPackages(ctx, url)
			if err != nil {
				return xerrors.Errorf("unable to fetch packages: %w", err)
			}

			filePath := filepath.Join(c.vulnListDir, debianDir, "Packages", code, r, "Packages.json")
			if err = utils.Write(filePath, headers); err != nil {
				return xerrors.Errorf("packages write error: %w", err)
			}
		}
	}
	return nil
}

func (c Client) fetchPackages(ctx context.Context, url string) ([]textproto.MIMEHeader, error) {
	tmpFile, err := utils.DownloadToTempFile(ctx, url)
	if err != nil {
		return nil, xerrors.Errorf("packages download error: %w", err)
	}
	defer os.Remove(tmpFile)

	headers, err := c.parsePackages(tmpFile)
	if err != nil {
		return nil, xerrors.Errorf("packages parse error: %w", err)
	}

	return headers, nil
}

func (c Client) parsePackages(packagePath string) ([]textproto.MIMEHeader, error) {
	f, err := os.Open(packagePath)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()

	var headers []textproto.MIMEHeader
	buf := new(bytes.Buffer)
	s := bufio.NewScanner(f)
	for s.Scan() {
		// Split into each package
		line := s.Text()
		buf.WriteString(line + "\n")
		if line != "" {
			continue
		}

		// Parse package detail
		r := textproto.NewReader(bufio.NewReader(buf))
		header, err := r.ReadMIMEHeader()
		if err != nil {
			return nil, xerrors.Errorf("MIME header error: %w", err)
		}
		headers = append(headers, header)
		buf.Reset()
	}

	return headers, nil
}

// end-of-life: EOL version
// lts: oldstable
// security: stable
// none && security+1: testing
func stableDist(dists map[string]Distribution) (int, error) {
	for _, dist := range dists {
		// "security" means stable version
		if dist.Support == "security" {
			return strconv.Atoi(dist.MajorVersion)
		}
	}
	return 0, xerrors.New("no stable version")
}

func supportedCodes(dists map[string]Distribution) ([]string, error) {
	stable, err := stableDist(dists)
	if err != nil {
		return nil, xerrors.Errorf("stable code: %w", err)
	}

	var codes []string
	for code, dist := range dists {
		// For sid
		if dist.MajorVersion == "" {
			continue
		}

		major, err := strconv.Atoi(dist.MajorVersion)
		if err != nil {
			return nil, xerrors.Errorf("failed to convert type to int")
		}

		// Only last-eol, oldstable, stable and testing are fetched
		// Older EOL versions do not have Packages.
		if stable-2 <= major && major < stable+2 {
			codes = append(codes, code)
		}
	}
	return codes, nil
}
