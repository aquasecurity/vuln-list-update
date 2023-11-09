package tracker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"log"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	trackerDir         = "tracker"
	securityTrackerURL = "https://salsa.debian.org/security-tracker-team/security-tracker/-/archive/master/security-tracker-master.tar.gz//security-tracker-master"
	sourcesURL         = "https://ftp.debian.org/debian/dists/%s/%s/source/Sources.gz"
	securitySourcesURL = "https://security.debian.org/debian-security/dists/%s/updates/%s/source/Sources.gz"
)

var (
	repos = []string{
		"main",
		"contrib",
		"non-free",
	}
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
	trackerURL         string
	sourcesURL         string
	securitySourcesURL string
	vulnListDir        string
}

type option func(*options)

func WithTrackerURL(url string) option {
	return func(opts *options) {
		opts.trackerURL = url
	}
}

func WithSourcesURL(url string) option {
	return func(opts *options) {
		opts.sourcesURL = url
	}
}

func WithSecuritySourcesURL(url string) option {
	return func(opts *options) {
		opts.securitySourcesURL = url
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
		trackerURL:         securityTrackerURL,
		sourcesURL:         sourcesURL,
		securitySourcesURL: securitySourcesURL,
		vulnListDir:        utils.VulnListDir(),
	}

	for _, opt := range opts {
		opt(o)
	}

	return Client{
		options: o,
		parsers: []listParser{
			cveList{},
			dlaList{},
			dsaList{},
		},
		annDispatcher: newAnnotationDispatcher(),
	}
}

func (c Client) Update() error {
	ctx := context.Background()

	log.Println("Removing old Debian data...")
	if err := os.RemoveAll(filepath.Join(c.vulnListDir, trackerDir)); err != nil {
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

	distributionJSON := filepath.Join(c.vulnListDir, trackerDir, "distributions.json")
	if err = utils.Write(distributionJSON, dists); err != nil {
		return xerrors.Errorf("unable to write %s: %w", distributionJSON, err)
	}

	err = c.updateSources(ctx, dists)
	if err != nil {
		return xerrors.Errorf("unable to fetch Sources: %w", err)
	}

	return nil
}

func (c Client) update(dirname string, bugs []Bug) error {
	// Save all JSON files
	log.Printf("Saving Debian %s data...", dirname)
	bar := pb.StartNew(len(bugs))
	for _, bug := range bugs {
		dir := filepath.Join(c.vulnListDir, trackerDir, dirname)
		if dirname == "CVE" {
			if strings.HasSuffix(bug.Header.ID, "-XXXX") {
				var bugno int
				for _, ann := range bug.Annotations {
					if ann.Type == "package" && ann.BugNo != 0 {
						bugno = ann.BugNo
						break
					}
				}

				bug.Header.ID = tempBugName(bugno, bug.Header.Description)

				fileName := fmt.Sprintf("%s.json", bug.Header.ID)
				filePath := filepath.Join(dir, "TEMP", fileName)
				if err := utils.Write(filePath, bug); err != nil {
					return xerrors.Errorf("debian: write error (%s): %w", filePath, err)
				}
			} else {
				if err := utils.SaveCVEPerYear(dir, bug.Header.ID, bug); err != nil {
					return xerrors.Errorf("debian: failed to save CVE per year: %w", err)
				}
			}
		} else {
			fileName := fmt.Sprintf("%s.json", bug.Header.ID)
			filePath := filepath.Join(dir, fileName)
			if err := utils.Write(filePath, bug); err != nil {
				return xerrors.Errorf("debian: write error (%s): %w", filePath, err)
			}
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
	)

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()

		switch {
		case line == "":
			continue
		case line[0] == ' ' || line[0] == '\t':
			if header == nil {
				log.Printf("header expected: %s", line)
				continue
			}

			ann := c.annDispatcher.parseAnnotation(line)
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
		// RESERVED should not have any information as below, but it is not always the case. We don't skip RESERVED here.
		// https://security-team.debian.org/security_tracker.html#reserved-entries
		if ann.Type == "REJECTED" || ann.Type == "NOT-FOR-US" {
			return false
		}
	}
	return true
}

func (c Client) updateSources(ctx context.Context, dists map[string]Distribution) error {
	for target, baseURL := range map[string]string{
		"source":         c.sourcesURL,
		"updates-source": c.securitySourcesURL,
	} {
		for code := range dists {
			for _, r := range repos {
				log.Printf("Updating %s %s/%s", target, code, r)
				url := fmt.Sprintf(baseURL, code, r)
				headers, err := c.fetchSources(ctx, url)
				if err != nil {
					return xerrors.Errorf("unable to fetch sources: %w", err)
				}

				for _, header := range headers {
					name := header.Get("Package")
					if name == "" {
						continue
					}

					filePath := filepath.Join(c.vulnListDir, trackerDir, target, code, r, name[:1], name+".json")
					if err = utils.Write(filePath, header); err != nil {
						return xerrors.Errorf("source write error: %w", err)
					}
				}
			}
		}
	}
	return nil
}

func (c Client) fetchSources(ctx context.Context, url string) ([]textproto.MIMEHeader, error) {
	tmpFile, err := utils.DownloadToTempFile(ctx, url)
	if err != nil {
		// Some codes don't have Sources in the repository
		if strings.Contains(err.Error(), "bad response code: 404") {
			return nil, nil
		}
		return nil, xerrors.Errorf("sources download error: %w", err)
	}
	defer os.Remove(tmpFile)

	headers, err := c.parseSources(tmpFile)
	if err != nil {
		return nil, xerrors.Errorf("sources parse error: %w", err)
	}

	return headers, nil
}

func (c Client) parseSources(sourcePath string) ([]textproto.MIMEHeader, error) {
	f, err := os.Open(sourcePath)
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

// ref. https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/50ca55fb66ec7592f9bc1053a11dbf0bd50ee425/lib/python/bugs.py#L402
func tempBugName(bugNumber int, description string) string {
	switch {
	case strings.HasPrefix(description, "["):
		description = strings.TrimPrefix(strings.TrimSuffix(description, "]"), "[")
	case strings.HasPrefix(description, "("):
		description = strings.TrimPrefix(strings.TrimSuffix(description, ")"), "(")
	}
	hash := fmt.Sprintf("%x", md5.Sum([]byte(description)))
	return fmt.Sprintf("TEMP-%07d-%s", bugNumber, strings.ToUpper(hash[:6]))
}
