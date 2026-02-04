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

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	retry = 3

	amazonDir = "amazon"
)

var (
	mirrorListURI = map[string]string{
		"1": "http://repo.us-west-2.amazonaws.com/2018.03/updates/x86_64/mirror.list",
		"2": "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list",
		// run `dnf repolist all --verbose` inside container to get `Repo-mirrors`
		"2022": "https://cdn.amazonlinux.com/al2022/core/mirrors/latest/x86_64/mirror.list",
		"2023": "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list",
	}
)

type Config struct {
	mirrorListURI map[string]string
	vulnListDir   string
}

type option func(*Config)

// With takes some internal values for testing
func With(mirrorListURI map[string]string, vulnListDir string) option {
	return func(opts *Config) {
		opts.mirrorListURI = mirrorListURI
		opts.vulnListDir = vulnListDir
	}
}

func NewConfig(opts ...option) *Config {
	config := &Config{
		mirrorListURI: mirrorListURI,
		vulnListDir:   utils.VulnListDir(),
	}

	for _, opt := range opts {
		opt(config)
	}

	return config
}

func (ac Config) Update() error {
	for version, amznURL := range ac.mirrorListURI {
		log.Printf("Fetching security advisories of Amazon Linux %s...\n", version)
		if err := ac.update(version, amznURL); err != nil {
			return xerrors.Errorf("failed to update security advisories of Amazon Linux %s: %w", version, err)
		}
	}
	return nil
}

func (ac Config) update(version, url string) error {
	dir := filepath.Join(ac.vulnListDir, amazonDir, version)
	if err := os.RemoveAll(dir); err != nil {
		return xerrors.Errorf("unable to remove amazon directory: %w", err)
	}
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}

	vulns, err := fetchUpdateInfoAmazonLinux(url)
	if err != nil {
		return xerrors.Errorf("failed to fetch security advisories from Amazon Linux Security Center: %w", err)
	}

	bar := pb.StartNew(len(vulns.ALASList))
	for _, alas := range vulns.ALASList {
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
			return nil, xerrors.Errorf("failed to parse mirror URL: %w", err)
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
