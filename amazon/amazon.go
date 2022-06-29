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
	"sort"

	"github.com/aquasecurity/vuln-list-update/utils"
	"golang.org/x/net/html/charset"
	"golang.org/x/xerrors"
	"gopkg.in/cheggaaa/pb.v1"
)

const (
	retry = 3

	amazonDir                 = "amazon"
	al2022ReleasemdURI        = "https://al2022-repos-us-west-2-9761ab97.s3.dualstack.us-west-2.amazonaws.com/core/releasemd.xml"
	al2022MirrorListURIFormat = "https://al2022-repos-us-east-1-9761ab97.s3.dualstack.us-east-1.amazonaws.com/core/mirrors/%s/x86_64/mirror.list"
)

var (
	linuxMirrorListURI = map[string]string{
		"1": "http://repo.us-west-2.amazonaws.com/2018.03/updates/x86_64/mirror.list",
		"2": "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list",
	}
)

type Config struct {
	LinuxMirrorListURI        map[string]string
	VulnListDir               string
	AL2022ReleasemdURI        string
	AL2022MirrorListURIFormat string
}

func NewConfig() Config {
	return Config{
		LinuxMirrorListURI:        linuxMirrorListURI,
		VulnListDir:               utils.VulnListDir(),
		AL2022MirrorListURIFormat: al2022MirrorListURIFormat,
		AL2022ReleasemdURI:        al2022ReleasemdURI,
	}
}

func (ac Config) Update() error {
	mirrorList2022, err := fetchAmazonLinux2022MirrorList(ac.AL2022ReleasemdURI, ac.AL2022MirrorListURIFormat)
	if err != nil {
		return xerrors.Errorf("failed to fetch mirror list of Amazon Linux 2022: %w", err)
	}
	ac.LinuxMirrorListURI["2022"] = mirrorList2022

	for version, amznURL := range ac.LinuxMirrorListURI {
		log.Printf("Fetching security advisories of Amazon Linux %s...\n", version)
		if err := ac.update(version, amznURL); err != nil {
			return xerrors.Errorf("failed to update security advisories of Amazon Linux %s: %w", version, err)
		}
	}
	return nil
}

func (ac Config) update(version, url string) error {
	dir := filepath.Join(ac.VulnListDir, amazonDir, version)
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

func fetchAmazonLinux2022MirrorList(url, format string) (string, error) {
	res, err := utils.FetchURL(url, "", retry)
	if err != nil {
		return "", xerrors.Errorf("Failed to fetch releasemd.xml for AL2022. url: %s, err: %w", al2022ReleasemdURI, err)
	}

	var root Root
	// releasemd file has mistake: encoding="utf8" instead of "utf-8"
	// https://stackoverflow.com/a/32224438
	decoder := xml.NewDecoder(bytes.NewBuffer(res))
	decoder.CharsetReader = charset.NewReaderLabel
	if err := decoder.Decode(&root); err != nil {
		return "", xerrors.Errorf("failed to decode releasemd.xml: %w", err)
	}

	var versions []string
	for _, release := range root.Releases.Release {
		versions = append(versions, release.Version)
	}

	if len(versions) == 0 {
		return "", xerrors.Errorf("list of Amazon Linux releases is empty")
	}

	// latest release contains all recommendations from previous releases
	// version format like "2022.0.20220531"
	sort.Sort(sort.StringSlice(versions))
	return fmt.Sprintf(format, versions[len(versions)-1]), nil
}
