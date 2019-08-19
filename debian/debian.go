package debian

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
	debianDir = "debian"
)

type DebianJSON map[string]DebianCveMap

type DebianCveMap map[string]interface{}

func Update() error {
	log.Println("Fetching Debian data...")
	vulns, err := retrieveDebianCveDetails()
	if err != nil {
		return xerrors.Errorf("failed to retrieve Debian CVE details: %w", err)
	}

	bar := pb.StartNew(len(vulns))
	for pkgName, cves := range vulns {
		for cveID, cve := range cves {
			dir := filepath.Join(utils.VulnListDir(), debianDir, pkgName)
			os.MkdirAll(dir, os.ModePerm)
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

// https://security-tracker.debian.org/tracker/data/json
func retrieveDebianCveDetails() (vulns DebianJSON, err error) {
	url := "https://security-tracker.debian.org/tracker/data/json"
	cveJSON, err := utils.FetchURL(url, "", 5)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch cve data from Debian. err: %w", err)
	}

	if err = json.Unmarshal(cveJSON, &vulns); err != nil {
		return nil, xerrors.Errorf("error in unmarshal json: %w", err)
	}

	return vulns, nil
}
