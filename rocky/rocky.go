package rocky

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/cheggaaa/pb/v3"
	"golang.org/x/xerrors"
)

const (
	retry    = 3
	rockyDir = "rocky"
)

var (
	urlFormat = "https://mirrors.rockylinux.org/mirrorlist?release=%s&repo=%s-%s&arch=%s"
	releases  = []string{"8"}
	repos     = []string{"BaseOS", "AppStream", "Devel"}
	archs     = []string{"x86_64", "aarch64"}
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

// UpdateInfo has a list
type UpdateInfo struct {
	RLSAList []RLSA `xml:"update"`
}

// RLSA has detailed data of RLSA
type RLSA struct {
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

// Date has time information
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

type options struct {
	urls  map[string]map[string]map[string]string
	dir   string
	retry int
}

type option func(*options)

func WithURLs(urls map[string]map[string]map[string]string) option {
	return func(opts *options) { opts.urls = urls }
}

func WithDir(dir string) option {
	return func(opts *options) { opts.dir = dir }
}

func WithRetry(retry int) option {
	return func(opts *options) { opts.retry = retry }
}

type Config struct {
	*options
}

func NewConfig(opts ...option) Config {
	urls := map[string]map[string]map[string]string{}
	for _, release := range releases {
		urls[release] = map[string]map[string]string{}
		for _, repo := range repos {
			urls[release][repo] = map[string]string{}
			for _, arch := range archs {
				urls[release][repo][arch] = fmt.Sprintf(urlFormat, release, repo, release, arch)
			}
		}
	}

	o := &options{
		urls:  urls,
		dir:   filepath.Join(utils.VulnListDir(), rockyDir),
		retry: retry,
	}

	for _, opt := range opts {
		opt(o)
	}

	return Config{
		options: o,
	}
}

func (c Config) Update() error {
	for release, repos := range c.urls {
		for repo, archs := range repos {
			for arch, url := range archs {
				log.Printf("Fetching Rocky Linux %s %s %s data...\n", release, repo, arch)
				if err := c.update(release, repo, arch, url); err != nil {
					return xerrors.Errorf("failed to update security advisories of Rocky Linux %s %s %s: %w", release, repo, arch, err)
				}
			}
		}
	}
	return nil
}

func (c Config) update(release, repo, arch, mirrorlist string) error {
	dirPath := filepath.Join(c.dir, release, repo, arch)
	log.Printf("Remove Rocky Linux %s %s %s directory %s\n", release, repo, arch, dirPath)
	if err := os.RemoveAll(dirPath); err != nil {
		return xerrors.Errorf("failed to remove Rocky Linux %s %s %s directory: %w", release, repo, arch, err)
	}
	if err := os.MkdirAll(dirPath, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}

	body, err := utils.FetchURL(mirrorlist, "", c.retry)
	if err != nil {
		return xerrors.Errorf("failed to fetch mirrorlist for Rocky Linux: %w", err)
	}

	// mirrorlist format(L1: header, L2~: mirror URL)
	// 1: # repo = rocky-BaseOS-8.4 arch = aarch64 country = JP country = ID country = KR country = CN country = GE country = TW country = AF country = KH country = PK country = HK country = CY
	// 2: http://ftp.riken.jp/Linux/rocky/8.4/BaseOS/aarch64/os/
	// 3: https://ftp.yz.yamagata-u.ac.jp/pub/Linux/rocky-linux/8.4/BaseOS/aarch64/os/
	// 4: ...
	mirrorURLs := strings.Split(string(body), "\n")
	if len(mirrorURLs) < 2 {
		return xerrors.New("invalid mirrorlist format")
	}

	u, err := url.Parse(mirrorURLs[1])
	if err != nil {
		return xerrors.Errorf("failed to parse mirror url: %w", err)
	}
	// Path check: minimum Path pattern(/8.4/BaseOS/aarch64/os/)
	ss := strings.Split(filepath.Clean(u.Path), "/")
	if len(ss) < 5 {
		return xerrors.Errorf("invalid mirror url path: %s", u.Path)
	}
	// u.Path: /Linux/rocky/8.4/BaseOS/aarch64/os/
	// path.Join(ss[1:len(ss)-4]...): /Linux/rocky
	// path.Join(ss[len(ss)-3:]...): /BaseOS/aarch64/os
	// rootPath: /Linux/rocky/${release}/BaseOS/aarch64/os
	rootPath := path.Join(path.Join(ss[1:len(ss)-4]...), release, path.Join(ss[len(ss)-3:]...))
	u.Path = path.Join(rootPath, "/repodata/repomd.xml")

	updateInfoPath, err := fetchUpdateInfoPath(u.String())
	if err != nil {
		return xerrors.Errorf("failed to fetch updateInfo path from repomd.xml: %w", err)
	}

	u.Path = path.Join(rootPath, updateInfoPath)
	uinfo, err := fetchUpdateInfo(u.String())
	if err != nil {
		return xerrors.Errorf("failed to fetch updateInfo: %w", err)
	}

	secErrata := map[string][]RLSA{}
	for _, rlsa := range uinfo.RLSAList {
		if !strings.HasPrefix(rlsa.ID, "RLSA-") {
			continue
		}

		issuedDate, err := time.Parse("2006-01-02 15:04:05", rlsa.Issued.Date)
		if err != nil {
			return xerrors.Errorf("failed to parse issued date: %w", err)
		}
		y := strconv.Itoa(issuedDate.Year())
		secErrata[y] = append(secErrata[y], rlsa)
	}

	for year, errata := range secErrata {
		log.Printf("Write Errata for Rocky Linux %s %s %s %s\n", release, repo, arch, year)

		if err := os.MkdirAll(filepath.Join(dirPath, year), os.ModePerm); err != nil {
			return xerrors.Errorf("failed to mkdir: %w", err)
		}

		bar := pb.StartNew(len(errata))
		for _, erratum := range errata {
			filepath := filepath.Join(dirPath, year, fmt.Sprintf("%s.json", erratum.ID))
			if err := utils.Write(filepath, erratum); err != nil {
				return xerrors.Errorf("failed to write Rocky Linux CVE details: %w", err)
			}
			bar.Increment()
		}
		bar.Finish()
	}

	return nil
}

func fetchUpdateInfoPath(repomdURL string) (updateInfoPath string, err error) {
	res, err := utils.FetchURL(repomdURL, "", retry)
	if err != nil {
		return "", xerrors.Errorf("failed to fetch %s: %w", repomdURL, err)
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
	for i, alas := range updateInfo.RLSAList {
		var cveIDs []string
		for _, ref := range alas.References {
			if ref.Type == "cve" {
				cveIDs = append(cveIDs, ref.ID)
			}
		}
		updateInfo.RLSAList[i].CveIDs = cveIDs
	}
	return &updateInfo, nil
}
