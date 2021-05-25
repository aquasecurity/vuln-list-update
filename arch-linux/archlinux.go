package arch_linux

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
	archLinuxDir          = "arch-linux"
	securityTrackerURL = "https://security.archlinux.org/json"
	retry              = 3
)


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

func (alc Client) Update() error {
	log.Println("Fetching Arch Linux data...")
	vulns, err := alc.retrieveArchLinuxCveDetails()
	if err != nil {
		return xerrors.Errorf("failed to retrieve Arch Linux CVE details: %w", err)
	}

	log.Println("Removing old data...")
	if err = os.RemoveAll(filepath.Join(alc.VulnListDir, archLinuxDir)); err != nil {
		return xerrors.Errorf("failed to remove Arch Linux dir: %w", err)
	}

	// Save all JSON files
	log.Println("Saving new data...")
	bar := pb.StartNew(len(vulns))
	for _, cves := range vulns {
			dir := filepath.Join(alc.VulnListDir, archLinuxDir)
			if err := os.MkdirAll(dir, os.ModePerm); err != nil {
				return xerrors.Errorf("failed to create the directory: %w", err)
			}
			filePath := filepath.Join(dir, fmt.Sprintf("%s.json", cves.Name))
			if err = utils.Write(filePath, cves); err != nil {
				return xerrors.Errorf("failed to write Debian CVE details: %w", err)
		}
		bar.Increment()
	}
	bar.Finish()
	return nil
}

func (alc Client) retrieveArchLinuxCveDetails() (vulns ArchLinuxCVE, err error) {
	cveJSON, err := utils.FetchURL(alc.URL, "", alc.Retry)
	if err != nil {
		return vulns, xerrors.Errorf("failed to fetch cve data from Arch Linux. err: %w", err)
	}

	if err = json.Unmarshal(cveJSON, &vulns); err != nil {
		return vulns, xerrors.Errorf("error in unmarshal json: %w", err)
	}
	return vulns, nil
}

