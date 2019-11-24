package suse

import (
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"
	pb "gopkg.in/cheggaaa/pb.v1"
)

var (
	SuseOSes = map[string][]string{
		// Version order is important
		OpenSUSELeap:          {"42.3", "15.0", "15.1"},
		SUSEEnterprise:        {"12", "15"},
		SUSEEnterpriseServer:  {"10", "11", "12", "15"},
		SUSEEnterpriseDesktop: {"10", "11", "12", "15"},
		// Do not correspond SUSEOpenstackCloud
		// SUSEOpenstackCloud:    {"7", "8", "9"},
	}
)

const (
	retry   = 5
	ovalDir = "oval"
	suseDir = "suse"
	ovalURL = "http://ftp.suse.com/pub/projects/security/oval/%s.%s.xml"
	// Some endpoint response 403 Fobidden
	// ovalURL = "https://support.novell.com/security/oval/%s.%s.xml"

	OpenSUSELeap          = "opensuse.leap"
	SUSEEnterprise        = "suse.linux.enterprise"
	SUSEEnterpriseServer  = "suse.linux.enterprise.server"
	SUSEEnterpriseDesktop = "suse.linux.enterprise.desktop"
	// Do not correspond SUSEOpenstackCloud
	// SUSEOpenstackCloud    = "suse.openstack.cloud"
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
		URL:         ovalURL,
		AppFs:       afero.NewOsFs(),
		Retry:       retry,
	}
}

func (c Config) Update() error {
	log.Print("Fetching SUSE data...")
	for os, versions := range SuseOSes {
		for _, ver := range versions {
			err := c.update(os, ver)
			if err != nil {
				return xerrors.Errorf("failed Update OVAL: %w", err)
			}
		}
	}
	return nil
}

func (c Config) update(os, ver string) error {
	res, err := utils.FetchURL(fmt.Sprintf(c.URL, os, ver), "", c.Retry)
	if err != nil {
		return xerrors.Errorf("failed to fetch %s %s OVAL: %w", os, ver, err)
	}
	var ov Oval
	err = xml.Unmarshal(res, &ov)
	if err != nil {
		return xerrors.Errorf("failed to decode SUSE XML: %w", err)
	}

	dir := filepath.Join(ovalDir, suseDir, os, ver)
	log.Printf("Fetching %s:%s data...", os, ver)
	bar := pb.StartNew(len(ov.Definitions))
	for _, def := range ov.Definitions {
		def.Description = strings.TrimSpace(def.Description)
		if err = c.saveCVEPerYear(dir, def.Title, def); err != nil {
			return xerrors.Errorf("failed to save CVE OVAL: %w", err)
		}
		bar.Increment()
	}
	bar.Finish()
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
