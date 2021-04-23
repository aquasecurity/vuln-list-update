package tracker

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/aquasecurity/vuln-list-update/utils"
	"golang.org/x/xerrors"
	pb "gopkg.in/cheggaaa/pb.v1"
)

const (
	debianDir          = "debian"
	securityTrackerURL = "https://security-tracker.debian.org/tracker/data/json"
	retry              = 5
)

type DebianJSON map[string]DebianCveMap

type DebianCveMap map[string]interface{}

type Client struct {
	URL         string
	VulnListDir string
	Retry       int
}

func NewClient() *Client {
	return &Client{
		URL:         securityTrackerURL,
		VulnListDir: utils.VulnListDir(),
		Retry:       retry,
	}
}

func (dc Client) Update() error {
	log.Println("Fetching Debian data...")
	vulns, err := dc.retrieveDebianCveDetails()
	if err != nil {
		return xerrors.Errorf("failed to retrieve Debian CVE details: %w", err)
	}

	log.Println("Removing old data...")
	if err = os.RemoveAll(filepath.Join(dc.VulnListDir, debianDir)); err != nil {
		return xerrors.Errorf("failed to remove Debian dir: %w", err)
	}

	// Save all JSON files
	log.Println("Saving new data...")
	bar := pb.StartNew(len(vulns))
	for pkgName, cves := range vulns {
		for cveID, cve := range cves {
			dir := filepath.Join(dc.VulnListDir, debianDir, pkgName)
			if err := os.MkdirAll(dir, os.ModePerm); err != nil {
				return xerrors.Errorf("failed to create the directory: %w", err)
			}
			filePath := filepath.Join(dir, fmt.Sprintf("%s.json", cveID))
			if err = utils.Write(filePath, cve); err != nil {
				return xerrors.Errorf("failed to write Debian CVE details: %w", err)
			}
		}
		bar.Increment()
	}
	bar.Finish()
	return nil
}

func (dc Client) retrieveDebianCveDetails() (vulns DebianJSON, err error) {
	cveJSON, err := utils.FetchURL(dc.URL, "", dc.Retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch cve data from Debian. err: %w", err)
	}

	if err = json.Unmarshal(cveJSON, &vulns); err != nil {
		return nil, xerrors.Errorf("error in unmarshal json: %w", err)
	}

	return vulns, nil
}
