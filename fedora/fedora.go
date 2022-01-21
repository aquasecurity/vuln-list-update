package fedora

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/cheggaaa/pb/v3"
	"github.com/ulikunitz/xz"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v2"
)

const (
	defaultConcurrency = 10
	defaultWait        = 1
	defaultRetry       = 3
	fedoraDir          = "fedora"
	dateFormat         = "2006-01-02 15:04:05"
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

	cveIDPattern = regexp.MustCompile(`(CVE-\d{4}-\d{4,})`)
	bugzillaURL  = "https://bugzilla.redhat.com/show_bug.cgi?ctype=xml&id=%s"
	moduleURL    = "https://kojipkgs.fedoraproject.org//packages/%s/%s/%d.%s/files/module/modulemd.%s.txt"
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
	Src      string `xml:"src,attr" json:"src,omitempty"`
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
	urls        map[string]string
	dir         string
	concurrency int
	wait        int
	retry       int
	releases    map[string][]string
	repos       []string
	arches      []string
}

type option func(*options)

func WithURLs(urls map[string]string) option {
	return func(opts *options) { opts.urls = urls }
}

func WithDir(dir string) option {
	return func(opts *options) { opts.dir = dir }
}

func WithConcurrency(concurrency int) option {
	return func(opts *options) { opts.concurrency = concurrency }
}

func WithWait(wait int) option {
	return func(opts *options) { opts.wait = wait }
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
		urls:        URIForamt,
		dir:         filepath.Join(utils.VulnListDir(), fedoraDir),
		concurrency: defaultConcurrency,
		wait:        defaultWait,
		retry:       defaultRetry,
		releases:    defaultReleases,
		repos:       defaultRepos,
		arches:      defaultArches,
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

	vulns, err := c.fetch(repo, arch, baseURL)
	if err != nil {
		return xerrors.Errorf("failed to fetch updateinfo: %w", err)
	}

	fsalistByYear := map[string][]FSA{}
	for _, fsa := range vulns.FSAList {
		t, err := time.Parse(dateFormat, fsa.Issued.Date)
		if err != nil {
			return xerrors.Errorf("failed to parse issued date: %w", err)
		}
		y := fmt.Sprintf("%d", t.Year())
		fsalistByYear[y] = append(fsalistByYear[y], fsa)
	}

	log.Printf("Write Fedora Linux (%s) %s %s %s Errata \n", mode, release, repo, arch)
	bar := pb.StartNew(len(vulns.FSAList))
	for year, fsalist := range fsalistByYear {
		if err := os.Mkdir(filepath.Join(dirPath, year), os.ModePerm); err != nil {
			return xerrors.Errorf("failed to mkdir: %w", err)
		}
		for _, fsa := range fsalist {
			filepath := filepath.Join(dirPath, year, fmt.Sprintf("%s.json", fsa.ID))
			if err := utils.Write(filepath, fsa); err != nil {
				return xerrors.Errorf("failed to write Fedora CVE details: %w", err)
			}
			bar.Increment()
		}
	}
	bar.Finish()

	return nil
}

func (c Config) fetch(repo, arch, baseURL string) (*UpdateInfo, error) {
	if repo == "Modular" {
		uinfo, err := c.fetchUpdateInfoModular(baseURL, arch)
		if err != nil {
			return nil, xerrors.Errorf("failed to fetch updateinfo for Modular Package: %w", err)
		}
		return uinfo, nil
	}
	uinfo, err := c.fetchUpdateInfoEverything(baseURL, arch)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch updateinfo for Everything Package: %w", err)
	}
	return uinfo, nil
}

func (c Config) fetchUpdateInfoEverything(baseURL, arch string) (*UpdateInfo, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse baseURL: %w", err)
	}
	originalPath := u.Path
	u.Path = path.Join(originalPath, "/repodata/repomd.xml")

	updateInfoPath, err := c.fetchRepomdData(u.String())
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch updateinfo path from repomd.xml: %w", err)
	}

	u.Path = path.Join(originalPath, updateInfoPath)
	uinfo, err := c.fetchUpdateInfo(u.String(), filepath.Ext(updateInfoPath)[1:], arch)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch updateinfo data: %w", err)
	}

	return uinfo, nil
}

func (c Config) fetchUpdateInfoModular(baseURL, arch string) (*UpdateInfo, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse baseURL: %w", err)
	}

	resp, err := http.Get(u.String())
	if err != nil {
		return nil, xerrors.Errorf("failed to get request modular page: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &UpdateInfo{FSAList: []FSA{}}, nil
	}

	originalPath := u.Path
	u.Path = path.Join(originalPath, "/repodata/repomd.xml")

	updateInfoPath, err := c.fetchRepomdData(u.String())
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch updateinfo, modules path from repomd.xml: %w", err)
	}

	u.Path = path.Join(originalPath, updateInfoPath)
	uinfo, err := c.fetchUpdateInfo(u.String(), filepath.Ext(updateInfoPath)[1:], arch)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch updateinfo data: %w", err)
	}

	modules, err := c.fetchModules(uinfo, arch)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch updateinfo data: %w", err)
	}

	if err := extractModulesToUpdateInfo(uinfo, modules); err != nil {
		return nil, xerrors.Errorf("failed to extract modules to updateinfo: %w", err)
	}

	return uinfo, nil
}

func (c Config) fetchRepomdData(repomdURL string) (updateInfoPath string, err error) {
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
			updateInfoPath = repo.Location.Href
			break
		}
	}
	if updateInfoPath == "" {
		return "", xerrors.New("No updateinfo field in the repomd")
	}
	return updateInfoPath, nil
}

func (c Config) fetchUpdateInfo(url, compress, arch string) (*UpdateInfo, error) {
	res, err := utils.FetchURL(url, "", c.retry)
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
		return nil, xerrors.Errorf("failed to decode updateinfo: %w", err)
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

		cveIDs, err := c.fetchCVEIDs(fsa)
		if err != nil {
			return nil, xerrors.Errorf("failed to fetch CVE-IDs: %w", err)
		}
		fsa.CveIDs = cveIDs

		fsaList = append(fsaList, fsa)
	}
	return &UpdateInfo{FSAList: fsaList}, nil
}

func (c Config) fetchCVEIDs(fsa FSA) ([]string, error) {
	cveIDMap := map[string]struct{}{}
	for _, ref := range fsa.References {
		if strings.Contains(ref.Title, "CVE-") {
			if strings.Contains(ref.Title, "various flaws") && strings.Contains(ref.Title, "...") {
				cveIDs, err := c.fetchCVEIDsfromBugzilla(ref.ID)
				if err != nil {
					return nil, xerrors.Errorf("failed to fetch CVE-ID from Bugzilla: %w", err)
				}
				if len(cveIDs) == 0 {
					log.Printf("failed to fetch CVE-ID from Bugzilla XML alias elements. bugzilla url: %s\n", ref.Href)
					continue
				}
				for _, cveID := range cveIDs {
					cveIDMap[cveID] = struct{}{}
				}
			} else {
				cveIDs := cveIDPattern.FindAllString(ref.Title, -1)
				if strings.Count(ref.Title, "CVE-") != len(cveIDs) {
					log.Printf("failed to fetch CVE-ID from Reference Title. bugzilla ID: %s, title: %s\n", ref.ID, ref.Title)
					log.Println("Retry to get CVE-ID using Bugzilla API.")
					var err error
					cveIDs, err = c.fetchCVEIDsfromBugzilla(ref.ID)
					if err != nil {
						return nil, xerrors.Errorf("failed to fetch CVE-ID from Bugzilla: %w", err)
					}
				}
				for _, cveID := range cveIDs {
					cveIDMap[cveID] = struct{}{}
				}
			}
		}
	}
	if len(cveIDMap) == 0 {
		cveIDs := cveIDPattern.FindAllString(fsa.Description, -1)
		if len(cveIDs) == 0 {
			return []string{}, nil
		}
		for _, cveID := range cveIDs {
			cveIDMap[cveID] = struct{}{}
		}
	}

	cveIDs := []string{}
	for cveID := range cveIDMap {
		cveIDs = append(cveIDs, cveID)
	}
	return cveIDs, nil
}

type Bugzilla struct {
	Bug struct {
		Alias   string   `xml:"alias"`
		Blocked []string `xml:"blocked"`
	} `xml:"bug"`
}

func (c Config) fetchCVEIDsfromBugzilla(bugzillaID string) ([]string, error) {
	log.Printf("Fetching CVE-IDs using Bugzilla API. Root Bugzilla ID: %s\n", bugzillaID)

	url := fmt.Sprintf(bugzillaURL, bugzillaID)
	res, err := utils.FetchURL(url, "", c.retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch bugzilla xml: %w", err)
	}

	var root Bugzilla
	if err := xml.NewDecoder(bytes.NewReader(res)).Decode(&root); err != nil {
		return nil, xerrors.Errorf("failed to decode bugzilla xml: %w", err)
	}

	if root.Bug.Alias != "" {
		return []string{root.Bug.Alias}, nil
	}

	urls := []string{}
	for _, blocked := range root.Bug.Blocked {
		urls = append(urls, fmt.Sprintf(bugzillaURL, blocked))
	}
	xmlBytes, err := utils.FetchConcurrently(urls, c.concurrency, c.wait, c.retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch bugzilla xml: %w", err)
	}

	cveIDs := []string{}
	for _, xmlByte := range xmlBytes {
		var b Bugzilla
		if err := xml.NewDecoder(bytes.NewReader(xmlByte)).Decode(&b); err != nil {
			return nil, xerrors.Errorf("failed to decode bugzilla xml: %w", err)
		}
		if b.Bug.Alias != "" {
			cveIDs = append(cveIDs, b.Bug.Alias)
		}
	}

	return cveIDs, nil
}

func (c Config) fetchModules(uinfo *UpdateInfo, arch string) (map[string]ModuleInfo, error) {
	moduleURLs := []string{}
	for _, advisory := range uinfo.FSAList {
		module, err := parseModuleFromAdvisoryTitle(advisory.Title)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse moduleinfo: %w", err)
		}
		moduleURLs = append(moduleURLs, fmt.Sprintf(moduleURL, module.Name, module.Stream, module.Version, module.Context, arch))
	}
	if len(moduleURLs) == 0 {
		return map[string]ModuleInfo{}, nil
	}

	log.Printf("Fetching ModuleInfo from Build System Info...")
	reps, err := utils.FetchConcurrently(moduleURLs, c.concurrency, c.wait, c.retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch moduleinfo: %w", err)
	}

	modules := map[string]ModuleInfo{}
	for _, res := range reps {
		scanner := bufio.NewScanner(bytes.NewReader(res))
		var contents []string
		for scanner.Scan() {
			str := scanner.Text()
			switch str {
			case "---":
				{
					contents = []string{}
				}
			case "...":
				{
					var module ModuleInfo
					if err := yaml.NewDecoder(strings.NewReader(strings.Join(contents, "\n"))).Decode(&module); err != nil {
						return nil, xerrors.Errorf("failed to decode module info: %w", err)
					}
					if module.Version == 2 {
						modules[module.convertToUpdateInfoTitle()] = module
					}
				}
			default:
				{
					contents = append(contents, str)
				}
			}
		}
	}

	return modules, nil
}

func parseModuleFromAdvisoryTitle(title string) (Module, error) {
	ss := strings.Split(title, "-")
	name, stream := ss[0], ss[1]
	ss = strings.Split(ss[2], ".")
	ver, err := strconv.ParseInt(ss[0], 10, 64)
	if err != nil {
		return Module{}, xerrors.Errorf("failed to parse version of moduleinfo from title(%s) of advisory: %w", title, err)
	}
	ctx := ss[1]

	return Module{
		Name:    name,
		Stream:  stream,
		Version: ver,
		Context: ctx,
	}, nil
}

type ModuleInfo struct {
	Version int `yaml:"version"`
	Data    struct {
		Name      string `yaml:"name"`
		Stream    string `yaml:"stream"`
		Version   int64  `yaml:"version"`
		Context   string `yaml:"context"`
		Arch      string `yaml:"arch"`
		Artifacts struct {
			Rpms []string `yaml:"rpms"`
		} `yaml:"artifacts"`
	} `yaml:"data"`
}

func (m ModuleInfo) convertToUpdateInfoTitle() string {
	return fmt.Sprintf("%s-%s-%d.%s", m.Data.Name, m.Data.Stream, m.Data.Version, m.Data.Context)
}

func extractModulesToUpdateInfo(uinfo *UpdateInfo, modules map[string]ModuleInfo) error {
	for i, fsa := range uinfo.FSAList {
		m, ok := modules[fsa.Title]
		if !ok {
			log.Printf("failed to get module info. title: %s\n", fsa.Title)
			continue
		}

		uinfo.FSAList[i].Module = Module{
			Stream:  m.Data.Stream,
			Name:    m.Data.Name,
			Version: m.Data.Version,
			Arch:    m.Data.Arch,
			Context: m.Data.Context,
		}

		pkgs := []Package{}
		for _, filename := range m.Data.Artifacts.Rpms {
			name, ver, rel, epoch, arch, err := splitFileName(filename)
			if err != nil {
				return xerrors.Errorf("failed to split rpm filename: %w", err)
			}
			pkgs = append(pkgs, Package{
				Name:     name,
				Epoch:    epoch,
				Version:  ver,
				Release:  rel,
				Arch:     arch,
				Filename: fmt.Sprintf("%s-%s-%s.%s.rpm", name, ver, rel, arch),
			})
		}
		uinfo.FSAList[i].Packages = pkgs
	}
	return nil
}

// splitFileName returns a name, version, release, epoch, arch
func splitFileName(filename string) (name, ver, rel, epoch, arch string, err error) {
	filename = strings.TrimSuffix(filename, ".rpm")

	archIndex := strings.LastIndex(filename, ".")
	if archIndex == -1 {
		return "", "", "", "", "", xerrors.Errorf("failed to parse arch from filename: %s", filename)
	}
	arch = filename[archIndex+1:]

	relIndex := strings.LastIndex(filename[:archIndex], "-")
	if relIndex == -1 {
		return "", "", "", "", "", xerrors.Errorf("failed to parse release from filename: %s", filename)
	}
	rel = filename[relIndex+1 : archIndex]

	verIndex := strings.LastIndex(filename[:relIndex], "-")
	if verIndex == -1 {
		return "", "", "", "", "", xerrors.Errorf("failed to parse version from filename: %s", filename)
	}
	ver = filename[verIndex+1 : relIndex]

	epochIndex := strings.Index(ver, ":")
	if epochIndex == -1 {
		epoch = "0"
	} else {
		epoch = ver[:epochIndex]
		ver = ver[epochIndex+1:]
	}

	name = filename[:verIndex]
	return name, ver, rel, epoch, arch, nil
}
