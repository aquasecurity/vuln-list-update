package alma

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/cheggaaa/pb"
	"golang.org/x/xerrors"
)

const (
	almaLinuxDir = "alma"
	urlFormat    = "https://errata.almalinux.org/%s/errata.json"
	retry        = 3
)

var (
	AlmaReleaseVer = map[string]bool{
		"8": true,
	}
)

type almaErrata struct {
	ID           almaErrataOID         `json:"_id"`
	BsRepoID     almaErrataOID         `json:"bs_repo_id"`
	UpdateinfoID string                `json:"updateinfo_id"`
	Description  string                `json:"description"`
	Fromstr      string                `json:"fromstr"`
	IssuedDate   alamErrataDate        `json:"issued_date"`
	Pkglist      almaErrataPkglist     `json:"pkglist"`
	Module       almaErrataModule      `json:"module"`
	Pushcount    string                `json:"pushcount"`
	References   []alamErrataReference `json:"references"`
	Release      string                `json:"release"`
	Rights       string                `json:"rights"`
	Severity     string                `json:"severity"`
	Solution     string                `json:"solution"`
	Status       string                `json:"status"`
	Summary      string                `json:"summary"`
	Title        string                `json:"title"`
	Type         string                `json:"type"`
	UpdatedDate  alamErrataDate        `json:"updated_date"`
	Version      string                `json:"version"`
}

type almaErrataOID struct {
	OID string `json:"$oid,omitempty"`
}

type alamErrataDate struct {
	Date int64 `json:"$date"`
}

type almaErrataPkglist struct {
	Name      string              `json:"name"`
	Shortname string              `json:"shortname"`
	Packages  []almaErrataPackage `json:"packages"`
}

type almaErrataPackage struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	Release         string      `json:"release"`
	Epoch           string      `json:"epoch"`
	Arch            string      `json:"arch"`
	Src             string      `json:"src"`
	Filename        string      `json:"filename"`
	Sum             string      `json:"sum"`
	SumType         interface{} `json:"sum_type"`
	RebootSuggested int         `json:"reboot_suggested"`
}

type almaErrataModule struct {
	Stream  string `json:"stream,omitempty"`
	Name    string `json:"name,omitempty"`
	Version int64  `json:"version,omitempty"`
	Arch    string `json:"arch,omitempty"`
	Context string `json:"context,omitempty"`
}

type alamErrataReference struct {
	Href  string `json:"href"`
	Type  string `json:"type"`
	ID    string `json:"id"`
	Title string `json:"title"`
}

type Config struct {
	VulnListDir string
	URLs        map[string]string
	Retry       int
}

func NewConfig() Config {
	urls := map[string]string{}
	for version := range AlmaReleaseVer {
		urls[version] = fmt.Sprintf(urlFormat, version)
	}

	return Config{
		VulnListDir: utils.VulnListDir(),
		URLs:        urls,
		Retry:       retry,
	}
}

func (c Config) Update() error {
	for version, url := range c.URLs {
		log.Printf("Fetching security advisories of AlmaLinux %s ...\n", version)
		if err := c.update(version, url); err != nil {
			return xerrors.Errorf("failed to update security advisories of AlmaLinux %s: %w", version, err)
		}
	}
	return nil
}

func (c Config) update(version, url string) error {
	dirPath := filepath.Join(c.VulnListDir, almaLinuxDir, version)
	log.Printf("Remove AlmaLinux %s directory %s\n", version, dirPath)
	if err := os.RemoveAll(dirPath); err != nil {
		return xerrors.Errorf("failed to remove AlmaLinux %s directory: %w", version, err)
	}
	if err := os.MkdirAll(dirPath, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}

	body, err := utils.FetchURL(url, "", c.Retry)
	if err != nil {
		return xerrors.Errorf("failed to fetch security advisories from AlmaLinux: %w", err)
	}

	var erratas []almaErrata
	if err := json.Unmarshal(body, &erratas); err != nil {
		return xerrors.Errorf("failed to unmarshal json: %w", err)
	}

	var secErratas []almaErrata
	for _, errata := range erratas {
		if !strings.HasPrefix(errata.UpdateinfoID, "ALSA-") {
			continue
		}
		secErratas = append(secErratas, errata)
	}

	bar := pb.StartNew(len(secErratas))
	for _, errata := range secErratas {
		filepath := filepath.Join(dirPath, fmt.Sprintf("%s.json", errata.UpdateinfoID))
		if err := utils.Write(filepath, errata); err != nil {
			return xerrors.Errorf("failed to write AlmaLinux CVE details: %w", err)
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}
