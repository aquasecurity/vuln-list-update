package rocky

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
	"strings"

	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/cheggaaa/pb/v3"
	"github.com/ulikunitz/xz"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v2"
)

const (
	retry    = 3
	rockyDir = "rocky"
)

var (
	urlFormat       = "https://download.rockylinux.org/pub/rocky/%s/%s/%s/os/"
	defaultReleases = []string{"8"}
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

// RLSA has detailed data of Rocky Linux Security Advisory
type RLSA struct {
	ID          string      `xml:"id" json:"id,omitempty"`
	Title       string      `xml:"title" json:"title,omitempty"`
	Issued      Date        `xml:"issued" json:"issued,omitempty"`
	Updated     Date        `xml:"updated" json:"updated,omitempty"`
	Severity    string      `xml:"severity" json:"severity,omitempty"`
	Description string      `xml:"description" json:"description,omitempty"`
	Packages    []Package   `xml:"pkglist>collection>package" json:"packages,omitempty"`
	PkgLists    []PkgList   `json:"pkglists,omitempty"`
	References  []Reference `xml:"references>reference" json:"references,omitempty"`
	CveIDs      []string    `json:"cveids,omitempty"`
}

// PkgList has modular package information
type PkgList struct {
	Packages []Package `json:"packages,omitempty"`
	Module   Module    `json:"module,omitempty"`
}

// Module has module information
type Module struct {
	Stream  string `json:"stream,omitempty"`
	Name    string `json:"name,omitempty"`
	Version int64  `json:"version,omitempty"`
	Arch    string `json:"arch,omitempty"`
	Context string `json:"context,omitempty"`
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

func (p Package) String() string {
	return fmt.Sprintf("%s-%s:%s-%s.%s", p.Name, p.Epoch, p.Version, p.Release, p.Arch)
}

type options struct {
	url      string
	dir      string
	retry    int
	releases []string
	repos    []string
	arches   []string
}

type option func(*options)

func WithURL(url string) option {
	return func(opts *options) { opts.url = url }
}

func WithDir(dir string) option {
	return func(opts *options) { opts.dir = dir }
}

func WithRetry(retry int) option {
	return func(opts *options) { opts.retry = retry }
}

func WithReleases(releases []string) option {
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
		url:      urlFormat,
		dir:      filepath.Join(utils.VulnListDir(), rockyDir),
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
	for _, release := range c.releases {
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
	updateInfoPath, modulesPath, err := c.fetchUpdateInfoPath(u.String())
	if err != nil {
		return xerrors.Errorf("failed to fetch updateInfo path from repomd.xml: %w", err)
	}

	var modules map[string]ModuleInfo
	if modulesPath != "" {
		u.Path = path.Join(rootPath, modulesPath)
		modules, err = c.fetchModules(u.String())
		if err != nil {
			return xerrors.Errorf("failed to fetch modules info: %w", err)
		}
	}

	u.Path = path.Join(rootPath, updateInfoPath)
	uinfo, err := c.fetchUpdateInfo(u.String())
	if err != nil {
		return xerrors.Errorf("failed to fetch updateInfo: %w", err)
	}

	if err := extractModulesToUpdateInfo(uinfo, modules); err != nil {
		return xerrors.Errorf("failed to extract modules to updateinfo: %w", err)
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

func (c Config) fetchUpdateInfoPath(repomdURL string) (updateInfoPath, modulesPath string, err error) {
	res, err := utils.FetchURL(repomdURL, "", c.retry)
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
		}
		if repo.Type == "modules" {
			modulesPath = repo.Location.Href
		}
	}
	if updateInfoPath == "" {
		return "", "", xerrors.New("no updateinfo field in the repomd")
	}
	return updateInfoPath, modulesPath, nil
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

func (c Config) fetchModules(url string) (map[string]ModuleInfo, error) {
	res, err := utils.FetchURL(url, "", c.retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch modules: %w", err)
	}

	r, err := xz.NewReader(bytes.NewBuffer(res))
	if err != nil {
		return nil, xerrors.Errorf("failed to decompress modules: %w", err)
	}

	modules := map[string]ModuleInfo{}
	scanner := bufio.NewScanner(r)
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
					modules[module.String()] = module
				}
			}
		default:
			{
				contents = append(contents, str)
			}
		}
	}

	return modules, nil
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

func (m ModuleInfo) String() string {
	return fmt.Sprintf("%s:%s:%d:%s:%s", m.Data.Name, m.Data.Stream, m.Data.Version, m.Data.Context, m.Data.Arch)
}

func extractModulesToUpdateInfo(uinfo *UpdateInfo, modules map[string]ModuleInfo) error {
	if modules == nil {
		return nil
	}

	// pkgToModuleStr: convert from package information to moduleStr
	pkgToModuleStr := map[string]string{}
	for modularStr, module := range modules {
		for _, pkg := range module.Data.Artifacts.Rpms {
			pkgToModuleStr[pkg] = modularStr
		}
	}

	for i, rlsa := range uinfo.RLSAList {
		// moduleStrToPkgs: convert from moduleStr to the relevant pkgs of the module (moduleStr is "" if it is not a module package)
		moduleStrToPkgs := map[string][]Package{}
		for _, pkg := range rlsa.Packages {
			moduleStr := pkgToModuleStr[pkg.String()]
			moduleStrToPkgs[moduleStr] = append(moduleStrToPkgs[moduleStr], pkg)
		}

		pkgLists := []PkgList{}
		for modularStr, pkgs := range moduleStrToPkgs {
			if modularStr == "" {
				pkgLists = append(pkgLists, PkgList{
					Packages: pkgs,
				})
				continue
			}

			// list the packages related to the module
			module := modules[modularStr]
			pkgs := []Package{}
			for _, pkg := range module.Data.Artifacts.Rpms {
				name, ver, rel, epoch, arch, err := splitFileName(pkg)
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

			pkgLists = append(pkgLists, PkgList{
				Packages: pkgs,
				Module: Module{
					Stream:  module.Data.Stream,
					Name:    module.Data.Name,
					Version: module.Data.Version,
					Arch:    module.Data.Arch,
					Context: module.Data.Context,
				},
			})
		}

		uinfo.RLSAList[i].PkgLists = pkgLists
		uinfo.RLSAList[i].Packages = nil
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
