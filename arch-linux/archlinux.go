package arch_linux

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/aquasecurity/vuln-list-update/utils"
	pb "github.com/cheggaaa/pb/v3"
	"golang.org/x/xerrors"
)

const (
	archLinuxDir       = "arch-linux"
	securityTrackerURL = "https://security.archlinux.org/json"
)

type ArchLinuxConfig struct {
	URL         string
	VulnListDir string
	Retry       int
}

func NewArchLinuxConfig() ArchLinuxConfig {
	return NewArchLinuxWithConfig(securityTrackerURL, filepath.Join(utils.VulnListDir(), archLinuxDir), 5)
}

func NewArchLinuxWithConfig(url, path string, retryTimes int) ArchLinuxConfig {
	return ArchLinuxConfig{
		URL:         url,
		VulnListDir: path,
		Retry:       retryTimes,
	}
}

func (alc ArchLinuxConfig) Update() error {
	log.Println("Fetching Arch Linux data...")
	vulns, err := alc.retrieveArchLinuxCveDetails()
	if err != nil {
		return xerrors.Errorf("failed to retrieve Arch Linux CVE details: %w", err)
	}

	log.Println("Removing old data...")
	if err = os.RemoveAll(alc.VulnListDir); err != nil {
		return xerrors.Errorf("failed to remove Arch Linux dir: %w", err)
	}

	// Save all JSON files
	log.Println("Saving new data...")
	bar := pb.StartNew(len(vulns))
	dir := filepath.Join(alc.VulnListDir)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to create the directory: %w", err)
	}
	for _, cves := range vulns {
		filePath := filepath.Join(dir, fmt.Sprintf("%s.json", cves.Name))
		if err = utils.Write(filePath, cves); err != nil {
			return xerrors.Errorf("failed to write Debian CVE details: %w", err)
		}
		bar.Increment()
	}
	bar.Finish()
	return nil
}

func (alc ArchLinuxConfig) retrieveArchLinuxCveDetails() (vulns ArchLinuxCVE, err error) {
	cveJSON, err := utils.FetchURL(alc.URL, "", alc.Retry)
	if err != nil {
		return vulns, xerrors.Errorf("failed to fetch cve data from Arch Linux. err: %w", err)
	}

	if err = json.Unmarshal(cveJSON, &vulns); err != nil {
		return vulns, xerrors.Errorf("error in unmarshal json: %w", err)
	}
	return vulns, nil
}
