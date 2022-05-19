package rocky

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/cheggaaa/pb/v3"
	"golang.org/x/xerrors"
)

const (
	retry    = 3
	rockyDir = "rocky"
)

var (
	reposUrl        = "https://download.rockylinux.org/pub/rocky"
	urlFormat       = reposUrl + "/%s/%s/%s/os/"
	defaultReleases = []string{"8.5"}
	defaultRepos    = []string{"BaseOS", "AppStream", "extras"}
	defaultArches   = []string{"x86_64", "aarch64"}
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
	Src      string `xml:"src,attr" json:"src,omitempty"`
	Filename string `xml:"filename" json:"filename,omitempty"`
}

type options struct {
	url    string
	dir    string
	retry  int
	repos  []string
	arches []string
}

type option func(*options)

func With(url, dir string, retry int, repos, arches []string) option {
	return func(opts *options) {
		opts.url = url
		opts.dir = dir
		opts.retry = retry
		opts.repos = repos
		opts.arches = arches
	}
}

type Config struct {
	*options
}

func NewConfig(opts ...option) Config {
	o := &options{
		url:    urlFormat,
		dir:    filepath.Join(utils.VulnListDir(), rockyDir),
		retry:  retry,
		repos:  defaultRepos,
		arches: defaultArches,
	}
	for _, opt := range opts {
		opt(o)
	}

	return Config{
		options: o,
	}
}

func (c Config) Update() error {
	releases, err := GetReleasesList(reposUrl)
	if err != nil {
		return err
	}
	for _, release := range releases {
		for _, repo := range c.repos {
			for _, arch := range c.arches {
				log.Printf("Fetching Rocky Linux %s %s %s data...", release, repo, arch)
				if err := c.update(release, repo, arch); err != nil {
					return xerrors.Errorf("failed to update security advisories of Rocky Linux %s %s %s: %w", release, repo, arch, err)
				}
			}
		}
	}
	return nil
}

func (c Config) update(release, repo, arch string) error {
	dirPath := filepath.Join(c.dir, release, repo, arch)
	log.Printf("Remove Rocky Linux %s %s %s directory %s", release, repo, arch, dirPath)
	if err := os.RemoveAll(dirPath); err != nil {
		return xerrors.Errorf("failed to remove Rocky Linux %s %s %s directory: %w", release, repo, arch, err)
	}
	if err := os.MkdirAll(dirPath, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}

	u, err := url.Parse(fmt.Sprintf(c.url, release, repo, arch))
	if err != nil {
		return xerrors.Errorf("failed to parse root url: %w", err)
	}
	rootPath := u.Path
	u.Path = path.Join(rootPath, "repodata/repomd.xml")
	updateInfoPath, err := c.fetchUpdateInfoPath(u.String())
	if err != nil {
		if errors.Is(err, ErrorNoUpdateInfoField) && repo == "extras" {
			log.Printf("skip extras repository because updateinfo field is not in repomd.xml: %s", err)
			return nil
		}
		return xerrors.Errorf("failed to fetch updateInfo path from repomd.xml: %w", err)
	}
	u.Path = path.Join(rootPath, updateInfoPath)
	uinfo, err := c.fetchUpdateInfo(u.String())
	if err != nil {
		return xerrors.Errorf("failed to fetch updateInfo: %w", err)
	}

	secErrata := map[string][]RLSA{}
	for _, rlsa := range uinfo.RLSAList {
		if !strings.HasPrefix(rlsa.ID, "RLSA-") {
			continue
		}
		y := strings.Split(strings.TrimPrefix(rlsa.ID, "RLSA-"), ":")[0]
		secErrata[y] = append(secErrata[y], rlsa)
	}

	for year, errata := range secErrata {
		log.Printf("Write Errata for Rocky Linux %s %s %s %s", release, repo, arch, year)

		if err := os.MkdirAll(filepath.Join(dirPath, year), os.ModePerm); err != nil {
			return xerrors.Errorf("failed to mkdir: %w", err)
		}

		bar := pb.StartNew(len(errata))
		for _, erratum := range errata {
			jsonPath := filepath.Join(dirPath, year, fmt.Sprintf("%s.json", erratum.ID))
			if err := utils.Write(jsonPath, erratum); err != nil {
				return xerrors.Errorf("failed to write Rocky Linux CVE details: %w", err)
			}
			bar.Increment()
		}
		bar.Finish()
	}

	return nil
}

var ErrorNoUpdateInfoField = xerrors.New("no updateinfo field in the repomd")

func (c Config) fetchUpdateInfoPath(repomdURL string) (updateInfoPath string, err error) {
	res, err := utils.FetchURL(repomdURL, "", c.retry)
	if err != nil {
		return "", xerrors.Errorf("failed to fetch %s: %w", repomdURL, err)
	}

	var repoMd RepoMd
	if err := xml.NewDecoder(bytes.NewBuffer(res)).Decode(&repoMd); err != nil {
		return "", xerrors.Errorf("failed to decode repomd.xml: %w", err)
	}

	for _, repo := range repoMd.RepoList {
		if repo.Type == "updateinfo" {
			return repo.Location.Href, nil
		}
	}
	return "", ErrorNoUpdateInfoField
}

func (c Config) fetchUpdateInfo(url string) (*UpdateInfo, error) {
	res, err := utils.FetchURL(url, "", c.retry)
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

var GetReleasesList = func(reposUrl string) ([]string, error) {
	var releases []string
	releaseRegex := regexp.MustCompile(`\d+.\d+`)

	b, err := utils.FetchURL(reposUrl, "", retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to get list of releases: %w", err)
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(b))
	if err != nil {
		return nil, xerrors.Errorf("failed to read list of releases: %w", err)
	}

	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		if release := releaseRegex.FindString(s.Text()); release != "" {
			releases = append(releases, release)
		}
	})

	if len(releases) == 0 {
		return nil, xerrors.Errorf("failed to get list of releases: list is empty")
	}
	return releases, nil
}
