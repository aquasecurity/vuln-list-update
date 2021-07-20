package tracker

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	debianDir          = "debian"
	securityTrackerURL = "https://salsa.debian.org/security-tracker-team/security-tracker/-/archive/master/security-tracker-master.tar.gz//security-tracker-master/data"
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
	url string
	dir string
}

type option func(*options)

func WithURL(url string) option {
	return func(opts *options) {
		opts.url = url
	}
}

func WithVulnListDir(dir string) option {
	return func(opts *options) {
		opts.dir = dir
	}
}

type Client struct {
	url           string
	vulnListDir   string
	parsers       []listParser
	annDispatcher annotationDispatcher
}

func NewClient(opts ...option) Client {
	o := &options{
		url: securityTrackerURL,
		dir: utils.VulnListDir(),
	}

	for _, opt := range opts {
		opt(o)
	}

	return Client{
		url:           o.url,
		vulnListDir:   o.dir,
		parsers:       []listParser{cveList{}, dlaList{}, dsaList{}},
		annDispatcher: newAnnotationDispatcher(),
	}
}

func (dc Client) Update() error {
	ctx := context.Background()

	log.Println("Removing old Debian data...")
	if err := os.RemoveAll(filepath.Join(dc.vulnListDir, debianDir)); err != nil {
		return xerrors.Errorf("failed to remove Debian dir: %w", err)
	}

	log.Println("Fetching Debian data...")
	tmpDir, err := utils.DownloadToTempDir(ctx, dc.url)
	if err != nil {
		return xerrors.Errorf("failed to retrieve Debian Security Tracker: %w", err)
	}
	//defer os.RemoveAll(tmpDir)

	for _, p := range dc.parsers {
		list := filepath.Join(tmpDir, p.Dir(), "list")
		bugs, err := dc.parseList(p, list)
		if err != nil {
			return xerrors.Errorf("debian parse error: %w", err)
		}

		if err = dc.update(p.Dir(), bugs); err != nil {
			return xerrors.Errorf("debian update error: %w", err)
		}
	}

	return nil
}

func (dc Client) update(dirname string, bugs []Bug) error {
	// Save all JSON files
	log.Printf("Saving Debian %s data...", dirname)
	bar := pb.StartNew(len(bugs))
	for _, bug := range bugs {
		dir := filepath.Join(dc.vulnListDir, debianDir, dirname)
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return xerrors.Errorf("failed to create the directory (%s): %w", dir, err)
		}
		filePath := filepath.Join(dir, fmt.Sprintf("%s.json", bug.Header.ID))
		if err := utils.Write(filePath, bug); err != nil {
			return xerrors.Errorf("debian: write error (%s): %w", filePath, err)
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}

// ref. https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/50ca55fb66ec7592f9bc1053a11dbf0bd50ee425/lib/python/sectracker/parsers.py#L198
func (dc Client) parseList(parser listParser, filename string) ([]Bug, error) {
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

			ann := dc.annDispatcher.parseAnnotation(line, lineno)
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

	if header != nil && shouldStore(anns) {
		bugs = append(bugs, Bug{
			Header:      header,
			Annotations: anns,
		})
	}

	return bugs, nil
}

func shouldStore(anns []*Annotation) bool {
	for _, ann := range anns {
		if ann.Type == "RESERVED" || ann.Type == "REJECTED" || ann.Type == "NOT-FOR-US" {
			return false
		}
	}
	return true
}
