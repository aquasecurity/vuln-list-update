package fedora

import (
	"bytes"
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/cheggaaa/pb/v3"
	"github.com/ulikunitz/xz"
	"golang.org/x/xerrors"
)

const (
	retry = 3

	fedoraDir = "fedora"
)

var (
	URIForamt = map[string]string{
		"fedora": "https://dl.fedoraproject.org/pub/fedora/linux/updates/%s/%s/%s/",
		"epel7":  "https://dl.fedoraproject.org/pub/epel/%s/%s/",
		"epel":   "https://dl.fedoraproject.org/pub/epel/%s/%s/%s/",
	}

	defaultReleases = map[string][]string{
		"fedora": {"32", "33", "34", "35"},
		"epel":   {"7", "8", "9"},
	}
	defaultRepos  = []string{"Everything", "Modular"}
	defaultArches = []string{"x86_64", "aarch64"}

	pkgArchFilter = map[string][]string{
		"x86_64":  {"noarch", "x86_64", "i686"},
		"aarch64": {"noarch", "aarch64"},
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

// UpdateInfo has a list of Fedora Security Advisory
type UpdateInfo struct {
	FSAList []FSA `xml:"update"`
}

// FSA has detailed data of Fedora Security Advisory
type FSA struct {
	ID          string      `xml:"id" json:"id,omitempty"`
	Title       string      `xml:"title" json:"title,omitempty"`
	Type        string      `xml:"type,attr" json:"type,omitempty"`
	Issued      Date        `xml:"issued" json:"issued,omitempty"`
	Updated     Date        `xml:"updated" json:"updated,omitempty"`
	Severity    string      `xml:"severity" json:"severity,omitempty"`
	Description string      `xml:"description" json:"description,omitempty"`
	Packages    []Package   `xml:"pkglist>collection>package" json:"packages,omitempty"`
	Module      Module      `json:"module,omitempty"`
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

// Module has modular package information
type Module struct {
	Stream  string `json:"stream,omitempty"`
	Name    string `json:"name,omitempty"`
	Version int64  `json:"version,omitempty"`
	Arch    string `json:"arch,omitempty"`
	Context string `json:"context,omitempty"`
}

type options struct {
	urls     map[string]string
	dir      string
	retry    int
	releases map[string][]string
	repos    []string
	arches   []string
}

type option func(*options)

func WithURLs(urls map[string]string) option {
	return func(opts *options) { opts.urls = urls }
}

func WithDir(dir string) option {
	return func(opts *options) { opts.dir = dir }
}

func WithRetry(retry int) option {
	return func(opts *options) { opts.retry = retry }
}

func WithReleases(releases map[string][]string) option {
	return func(opts *options) { opts.releases = releases }
}

func WithRepos(repos []string) option {
	return func(opts *options) { opts.repos = repos }
}

func WithArches(arches []string) option {
	return func(opts *options) { opts.arches = arches }
}

type Config struct {
	*options
}

func NewConfig(opts ...option) Config {
	o := &options{
		urls:     URIForamt,
		dir:      filepath.Join(utils.VulnListDir(), fedoraDir),
		retry:    retry,
		releases: defaultReleases,
		repos:    defaultRepos,
		arches:   defaultArches,
	}
	for _, opt := range opts {
		opt(o)
	}

	return Config{
		options: o,
	}
}

func (c Config) Update() error {
	for mode, releases := range c.releases {
		for _, release := range releases {
			if mode == "epel" && release == "7" {
				for _, arch := range c.arches {
					log.Printf("Fetching Fedora Linux (%s) %s %s data...\n", mode, release, arch)
					if err := c.update(mode, release, "", arch); err != nil {
						return xerrors.Errorf("failed to update security advisories of Fedora Linux EPEL %s %s: %w", release, arch, err)
					}
				}
			} else {
				for _, repo := range c.repos {
					for _, arch := range c.arches {
						log.Printf("Fetching Fedora Linux (%s) %s %s %s data...\n", mode, release, repo, arch)
						if err := c.update(mode, release, repo, arch); err != nil {
							return xerrors.Errorf("failed to update security advisories of Fedora Linux EPEL %s %s %s: %w", release, repo, arch, err)
						}
					}
				}
			}
		}
	}
	return nil
}

func (c Config) update(mode, release, repo, arch string) error {
	var dirPath string
	var baseURL string
	if mode == "epel" {
		if release == "7" {
			dirPath = filepath.Join(c.dir, mode, release, arch)
			baseURL = fmt.Sprintf(c.urls["epel7"], release, arch)
		} else {
			dirPath = filepath.Join(c.dir, mode, release, repo, arch)
			baseURL = fmt.Sprintf(c.urls["epel"], release, repo, arch)
		}
	} else {
		dirPath = filepath.Join(c.dir, mode, release, repo, arch)
		baseURL = fmt.Sprintf(c.urls["fedora"], release, repo, arch)
	}
	log.Printf("Remove Fedora Linux (%s) %s %s %s directory %s\n", mode, release, repo, arch, dirPath)

	if err := os.RemoveAll(dirPath); err != nil {
		return xerrors.Errorf("failed to remove Fedora Linux (%s) %s %s %s directory: %w", mode, release, repo, arch, err)
	}
	if err := os.MkdirAll(dirPath, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}

	vulns, err := fetch(repo, arch, baseURL)
	if err != nil {
		return xerrors.Errorf("failed to fetch updateinfo: %w", err)
	}

	bar := pb.StartNew(len(vulns.FSAList))
	for _, fsa := range vulns.FSAList {
		filepath := filepath.Join(dirPath, fmt.Sprintf("%s.json", fsa.ID))
		if err := utils.Write(filepath, fsa); err != nil {
			return xerrors.Errorf("failed to write Fedora CVE details: %w", err)
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}

func fetch(repo, arch, baseURL string) (*UpdateInfo, error) {
	if repo == "Modular" {
		uinfo, err := fetchUpdateInfoModular(baseURL, arch)
		if err != nil {
			return nil, xerrors.Errorf("failed to fetch updateinfo for Modular Package: %w", err)
		}
		return uinfo, nil
	}
	uinfo, err := fetchUpdateInfoEverything(baseURL, arch)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch updateinfo for Everything Package: %w", err)
	}
	return uinfo, nil
}

func fetchUpdateInfoEverything(baseURL, arch string) (*UpdateInfo, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse repomd URL: %w", err)
	}
	originalPath := u.Path
	u.Path = path.Join(originalPath, "/repodata/repomd.xml")

	updateInfoPath, _, err := fetchRepomdData(u.String())
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch updateinfo path from repomd.xml: %w", err)
	}

	u.Path = path.Join(originalPath, updateInfoPath)
	uinfo, err := fetchUpdateInfo(u.String(), filepath.Ext(updateInfoPath)[1:], arch)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch updateinfo data: %w", err)
	}

	return uinfo, nil
}

func fetchUpdateInfoModular(baseURL, arch string) (*UpdateInfo, error) {
	return &UpdateInfo{}, nil
}

func fetchRepomdData(repomdURL string) (updateInfoPath, modulesPath string, err error) {
	res, err := utils.FetchURL(repomdURL, "", retry)
	if err != nil {
		return "", "", xerrors.Errorf("failed to fetch %s: %w", repomdURL, err)
	}

	var repoMd RepoMd
	if err := xml.NewDecoder(bytes.NewBuffer(res)).Decode(&repoMd); err != nil {
		return "", "", xerrors.Errorf("failed to decode repomd.xml: %w", err)
	}

	for _, repo := range repoMd.RepoList {
		if repo.Type == "updateinfo" {
			updateInfoPath = repo.Location.Href
		} else if repo.Type == "modules" {
			modulesPath = repo.Location.Href
		}
	}
	if updateInfoPath == "" {
		return "", "", xerrors.New("No updateinfo field in the repomd")
	}
	return updateInfoPath, modulesPath, nil
}

func fetchUpdateInfo(url, compress, arch string) (*UpdateInfo, error) {
	res, err := utils.FetchURL(url, "", retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch updateInfo: %w", err)
	}

	var r io.Reader
	switch compress {
	case "xz":
		r, err = xz.NewReader(bytes.NewBuffer(res))
		if err != nil {
			return nil, xerrors.Errorf("failed to decompress updateInfo: %w", err)
		}
	case "bz2":
		r = bzip2.NewReader(bytes.NewBuffer(res))
	}

	var updateInfo UpdateInfo
	if err := xml.NewDecoder(r).Decode(&updateInfo); err != nil {
		return nil, err
	}
	fsaList := []FSA{}
	for _, fsa := range updateInfo.FSAList {
		if fsa.Type != "security" {
			continue
		}

		var pkgs []Package
		for _, pkg := range fsa.Packages {
			if utils.StringInSlice(pkg.Arch, pkgArchFilter[arch]) {
				pkgs = append(pkgs, pkg)
			}
		}
		fsa.Packages = pkgs

		var cveIDs []string
		for _, ref := range fsa.References {
			if strings.Contains(ref.Href, "CVE-") {
				cveID, err := fetchCVEIDfromBugzilla(ref.Href)
				if err != nil {
					return nil, xerrors.Errorf("failed to fetch CVE-ID from Bugzilla: %w", err)
				}
				if cveID == "" {
					log.Printf("failed to fetch CVE-ID from Bugzilla XML alias elements. bugzilla url: %s", ref.Href)
					continue
				}
				cveIDs = append(cveIDs, cveID)
			}
		}
		fsa.CveIDs = cveIDs

		fsaList = append(fsaList, fsa)
	}
	return &UpdateInfo{FSAList: fsaList}, nil
}

type Bugzilla struct {
	Bug struct {
		Alias string `xml:"alias"`
	} `xml:"bug"`
}

func fetchCVEIDfromBugzilla(bugzillaURL string) (string, error) {
	u, err := url.Parse(bugzillaURL)
	if err != nil {
		return "", xerrors.Errorf("failed to parse bugzilla URL: %w", err)
	}
	q := u.Query()
	q.Set("ctype", "xml")
	u.RawQuery = q.Encode()

	res, err := utils.FetchURL(u.String(), "", retry)
	if err != nil {
		return "", xerrors.Errorf("failed to fetch bugzilla xml: %w", err)
	}

	var bugzilla Bugzilla
	if err := xml.NewDecoder(bytes.NewReader(res)).Decode(&bugzilla); err != nil {
		return "", xerrors.Errorf("failed to decode bugzilla xml: %w", err)
	}

	return bugzilla.Bug.Alias, nil
}
