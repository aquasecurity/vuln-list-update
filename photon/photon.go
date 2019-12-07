package photon

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/cheggaaa/pb"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"
)

const (
	advisoryURL    = "https://vmware.bintray.com/photon_cve_metadata/"
	versionsFile   = "photon_versions.json"
	advisoryFormat = "cve_data_photon%s.json"

	photonDir = "photon"
	retry     = 5
)

type Config struct {
	VulnListDir string
	URL         string
	AppFs       afero.Fs
	Retry       int
}

func NewConfig() Config {
	return Config{
		VulnListDir: utils.VulnListDir(),
		URL:         advisoryURL,
		AppFs:       afero.NewOsFs(),
		Retry:       retry,
	}
}

func (c Config) getPhotonVersion() ([]string, error) {
	var versions Versions
	res, err := utils.FetchURL(c.URL+versionsFile, "", c.Retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch Photon advisory: %w", err)
	}
	if err := json.Unmarshal(res, &versions); err != nil {
		return nil, xerrors.Errorf("failed to decode Photon advisory: %w", err)
	}

	return versions.Branches, nil
}

func (c Config) Update() error {
	log.Printf("Fetching Photon")

	versions, err := c.getPhotonVersion()
	if err != nil {
		return xerrors.Errorf("failed to fetch Photon versions: %w", err)
	}
	for _, version := range versions {
		res, err := utils.FetchURL(c.URL+fmt.Sprintf(advisoryFormat, version), "", c.Retry)
		if err != nil {
			return xerrors.Errorf("failed to fetch Photon advisory: %w", err)
		}
		var cves []PhotonCVE
		if err := json.Unmarshal(res, &cves); err != nil {
			return xerrors.Errorf("failed to unmarshal Photon advisory: %w", err)
		}
		dir := filepath.Join(photonDir, version)

		bar := pb.StartNew(len(cves))
		for _, def := range cves {
			def.OSVersion = version
			if err = c.saveCVEPerYear(dir, def.CveID, def); err != nil {
				return xerrors.Errorf("failed to save CVEPerYear: %w", err)
			}
			bar.Increment()
		}
		bar.Finish()
	}

	return nil
}

func (c Config) saveCVEPerYear(dirName string, cveID string, data interface{}) error {
	s := strings.Split(cveID, "-")
	if len(s) != 3 {
		return xerrors.Errorf("invalid CVE-ID format: %s\n", cveID)
	}

	yearDir := filepath.Join(c.VulnListDir, dirName, s[1])
	if err := c.AppFs.MkdirAll(yearDir, os.ModePerm); err != nil {
		return err
	}

	filePath := filepath.Join(yearDir, fmt.Sprintf("%s.json", cveID))

	fs := utils.NewFs(c.AppFs)
	if err := fs.WriteJSON(filePath, data); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}
