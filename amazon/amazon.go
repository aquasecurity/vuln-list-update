package amazon

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"

	"github.com/aquasecurity/vuln-list-update/utils"
	"golang.org/x/xerrors"
	"gopkg.in/cheggaaa/pb.v1"
)

const (
	retry = 3

	amazonDir = "amazon"
)

var (
	LinuxMirrorListURI = map[string]string{
		"1": "http://repo.us-west-2.amazonaws.com/2018.03/updates/x86_64/mirror.list",
		"2": "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list",
	}
)

// RepoMd has repomd data
type RepoMd struct {
	RepoList []Repo `xml:"data"`
}

// Repo has a repo data
type Repo struct {
	Type     string   `xml:"type,attr"`
	Location Location `xml:"location"`
}

// Location has a location of repomd
type Location struct {
	Href string `xml:"href,attr"`
}

// UpdateInfo has a list of ALAS
type UpdateInfo struct {
	ALASList []ALAS `xml:"update"`
}

// ALAS has detailed data of ALAS
type ALAS struct {
	ID          string      `xml:"id" json:"id,omitempty"`
	Title       string      `xml:"title" json:"title,omitempty"`
	Issued      Date        `xml:"issued" json:"issued,omitempty"`
	Updated     Date        `xml:"updated" json:"updated,omitempty"`
	Severity    string      `xml:"severity" json:"severity,omitempty"`
	Description string      `xml:"description" json:"description,omitempty"`
	Packages    []Package   `xml:"pkglist>collection>package" json:"packages,omitempty"`
	References  []Reference `xml:"references>reference" json:"references,omitempty"`
	CveIDs      []string    `json:"cveids,omitempty"`
}

// Updated has updated at
type Date struct {
	Date string `xml:"date,attr" json:"date,omitempty"`
}

// Reference has reference information
type Reference struct {
	Href  string `xml:"href,attr" json:"href,omitempty"`
	ID    string `xml:"id,attr" json:"id,omitempty"`
	Title string `xml:"title,attr" json:"title,omitempty"`
	Type  string `xml:"type,attr" json:"type,omitempty"`
}

// Package has affected package information
type Package struct {
	Name     string `xml:"name,attr" json:"name,omitempty"`
	Epoch    string `xml:"epoch,attr" json:"epoch,omitempty"`
	Version  string `xml:"version,attr" json:"version,omitempty"`
	Release  string `xml:"release,attr" json:"release,omitempty"`
	Arch     string `xml:"arch,attr" json:"arch,omitempty"`
	Filename string `xml:"filename" json:"filename,omitempty"`
}

type Config struct {
	LinuxMirrorListURI map[string]string
	VulnListDir        string
}

func (ac Config) Update() error {
	// version = 1 or 2
	for version, amznURL := range ac.LinuxMirrorListURI {
		log.Printf("Fetching security advisories of Amazon Linux %s...\n", version)
		if err := ac.update(version, amznURL); err != nil {
			return xerrors.Errorf("failed to update security advisories of Amazon Linux %s: %w", version, err)
		}
	}
	return nil
}

func (ac Config) update(version, url string) error {
	vulns, err := fetchUpdateInfoAmazonLinux(url)
	if err != nil {
		return xerrors.Errorf("failed to fetch security advisories from Amazon Linux Security Center: %w", err)
	}

	bar := pb.StartNew(len(vulns.ALASList))
	for _, alas := range vulns.ALASList {
		dir := filepath.Join(ac.VulnListDir, amazonDir, version)
		if err = os.MkdirAll(dir, os.ModePerm); err != nil {
			return xerrors.Errorf("failed to mkdir: %w", err)
		}
		filePath := filepath.Join(dir, fmt.Sprintf("%s.json", alas.ID))
		if err = utils.Write(filePath, alas); err != nil {
			return xerrors.Errorf("failed to write Amazon CVE details: %w", err)
		}
		bar.Increment()
	}
	bar.Finish()

	return nil

}

func fetchUpdateInfoAmazonLinux(mirrorListURL string) (uinfo *UpdateInfo, err error) {
	body, err := utils.FetchURL(mirrorListURL, "", retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch mirror list files: %w", err)
	}

	var mirrors []string
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		mirrors = append(mirrors, scanner.Text())
	}

	for _, mirror := range mirrors {
		u, err := url.Parse(mirror)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse mirror URL: %w")
		}
		originalPath := u.Path
		u.Path = path.Join(u.Path, "/repodata/repomd.xml")

		updateInfoPath, err := fetchUpdateInfoURL(u.String())
		if err != nil {
			log.Printf("Failed to fetch updateInfo URL: %s\n", err)
			continue
		}

		u.Path = path.Join(originalPath, updateInfoPath)
		uinfo, err := fetchUpdateInfo(u.String())
		if err != nil {
			log.Printf("Failed to fetch updateInfo: %s\n", err)
			continue
		}
		return uinfo, nil
	}
	return nil, xerrors.New("Failed to fetch updateinfo")
}

func fetchUpdateInfoURL(mirror string) (updateInfoPath string, err error) {
	res, err := utils.FetchURL(mirror, "", retry)
	if err != nil {
		return "", xerrors.Errorf("failed to fetch %s: %w", mirror, err)
	}

	var repoMd RepoMd
	if err := xml.NewDecoder(bytes.NewBuffer(res)).Decode(&repoMd); err != nil {
		return "", xerrors.Errorf("failed to decode repomd.xml: %w", err)
	}

	for _, repo := range repoMd.RepoList {
		if repo.Type == "updateinfo" {
			updateInfoPath = repo.Location.Href
			fmt.Println(updateInfoPath)
			break
		}
	}
	if updateInfoPath == "" {
		return "", xerrors.New("No updateinfo field in the repomd")
	}
	return updateInfoPath, nil
}

func fetchUpdateInfo(url string) (*UpdateInfo, error) {
	res, err := utils.FetchURL(url, "", retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch updateInfo: %w", err)
	}
	r, err := gzip.NewReader(bytes.NewBuffer(res))
	if err != nil {
		return nil, xerrors.Errorf("failed to decompress updateInfo: %w", err)
	}
	defer r.Close()

	var updateInfo UpdateInfo
	if err := xml.NewDecoder(r).Decode(&updateInfo); err != nil {
		return nil, err
	}
	for i, alas := range updateInfo.ALASList {
		var cveIDs []string
		for _, ref := range alas.References {
			if ref.Type == "cve" {
				cveIDs = append(cveIDs, ref.ID)
			}
		}
		updateInfo.ALASList[i].CveIDs = cveIDs
	}
	return &updateInfo, nil
}
