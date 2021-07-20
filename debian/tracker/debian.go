package tracker

import (
	"bufio"
	"context"
	"log"
	"os"
	"path/filepath"

	"github.com/aquasecurity/vuln-list-update/utils"
	"golang.org/x/xerrors"
)

const (
	debianDir          = "debian"
	securityTrackerURL = "https://salsa.debian.org/security-tracker-team/security-tracker/-/archive/master/security-tracker-master.tar.gz//security-tracker-master/data"
	//securityTrackerURL = "https://salsa.debian.org/security-tracker-team/security-tracker/-/archive/master/security-tracker-master.tar.gz?path=data"
	//securityTrackerURL = "https://security-tracker.debian.org/tracker/data/json"
)

type Bug struct {
	Header      *Header
	Annotations []*Annotation
}

type listParser interface {
	ParseHeader(string) *Header
}

type Client struct {
	url           string
	VulnListDir   string
	annDispatcher annotationDispatcher
}

func NewClient() *Client {
	return &Client{
		url:           securityTrackerURL,
		VulnListDir:   utils.VulnListDir(),
		annDispatcher: newAnnotationDispatcher(),
	}
}

func (dc Client) Update() error {
	ctx := context.Background()

	log.Println("Fetching Debian data...")
	tmpDir, err := utils.DownloadToTempDir(ctx, dc.url)
	if err != nil {
		return xerrors.Errorf("failed to retrieve Debian CVE details: %w", err)
	}

	dataDir := filepath.Join(tmpDir, "security-tracker-master-data", "data")

	for _, d := range []string{"DLA"} {
		list := filepath.Join(dataDir, d, "list")
		dc.parseList(dlaList{}, list)
	}

	//log.Println("Removing old data...")
	//if err = os.RemoveAll(filepath.Join(dc.VulnListDir, debianDir)); err != nil {
	//	return xerrors.Errorf("failed to remove Debian dir: %w", err)
	//}
	//
	//// Save all JSON files
	//log.Println("Saving new data...")
	//bar := pb.StartNew(len(vulns))
	//for pkgName, cves := range vulns {
	//	for cveID, cve := range cves {
	//		dir := filepath.Join(dc.VulnListDir, debianDir, pkgName)
	//		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
	//			return xerrors.Errorf("failed to create the directory: %w", err)
	//		}
	//		filePath := filepath.Join(dir, fmt.Sprintf("%s.json", cveID))
	//		if err = utils.Write(filePath, cve); err != nil {
	//			return xerrors.Errorf("failed to write Debian CVE details: %w", err)
	//		}
	//	}
	//	bar.Increment()
	//}
	//bar.Finish()
	return nil
}

func (dc Client) parseList(parser listParser, filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return xerrors.Errorf("unable to open %s: %w", filename, err)
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
				bug := Bug{
					Header:      header,
					Annotations: anns,
				}
				bugs = append(bugs, bug)
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

	return nil
}
