package rocky

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

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
	defaultURL      = "https://download.rockylinux.org/%s/rocky/%s/%s/%s/os/repodata"
	defaultReleases = map[string]map[string][]string{"8": {"vault": {"8.3", "8.4"}, "pub": {"8.5"}}}
	defaultRepos    = []string{"BaseOS", "AppStream", "extras"}
	// defaultArches   = []string{"x86_64", "aarch64"}
	defaultArches = []string{"x86_64"}
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
	Advisories []Advisory `xml:"update"`
}

// Advisory has detailed data of Rocky Linux Advisory
type Advisory struct {
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

func (m Module) String() string {
	return fmt.Sprintf("%s:%s:%d:%s:%s", m.Name, m.Stream, m.Version, m.Context, m.Arch)
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

func (p Package) String() string {
	return fmt.Sprintf("%s-%s:%s-%s.%s", p.Name, p.Epoch, p.Version, p.Release, p.Arch)
}

type options struct {
	url      string
	dir      string
	retry    int
	releases map[string]map[string][]string
	repos    []string
	arches   []string
}

type option func(*options)

func With(url string, dir string, retry int, releases map[string]map[string][]string, repos, arches []string) option {
	return func(opts *options) {
		opts.url = url
		opts.dir = dir
		opts.retry = retry
		opts.releases = releases
		opts.repos = repos
		opts.arches = arches
	}
}

type Config struct {
	*options
}

func NewConfig(opts ...option) Config {
	o := &options{
		url:      defaultURL,
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
	for majorVer, releases := range c.releases {
		for _, repo := range c.repos {
			for _, arch := range c.arches {
				log.Printf("Fetching Rocky Linux %s %s %s data...", majorVer, repo, arch)
				if err := c.update(majorVer, releases, repo, arch); err != nil {
					return xerrors.Errorf("failed to update security advisories of Rocky Linux %s %s %s: %w", majorVer, repo, arch, err)
				}
			}
		}
	}
	return nil
}

func (c Config) update(majorVer string, releases map[string][]string, repo, arch string) error {
	dirPath := filepath.Join(c.dir, majorVer, repo, arch)
	log.Printf("Remove Rocky Linux %s %s %s directory %s", majorVer, repo, arch, dirPath)
	if err := os.RemoveAll(dirPath); err != nil {
		return xerrors.Errorf("failed to remove Rocky Linux %s %s %s directory: %w", majorVer, repo, arch, err)
	}
	if err := os.MkdirAll(dirPath, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}

	advisories := map[string]Advisory{}
	for status, rels := range releases {
		for _, rel := range rels {
			u, err := url.Parse(fmt.Sprintf(c.url, status, rel, repo, arch))
			if err != nil {
				return xerrors.Errorf("failed to parse root url: %w", err)
			}
			rootPath := u.Path

			log.Printf("Fetching Rocky Linux %s %s %s Advisory filename from repodata html...", rel, repo, arch)
			advFiles, err := c.fetchAdvisoryFiles(u.String())
			if err != nil {
				return xerrors.Errorf("failed to fetch advisory files: %w", err)
			}

			for _, advFile := range advFiles {
				log.Printf("Fetching advisory. updateinfo.xml: %.10s, modules.yaml: %.10s", advFile.updateinfo, advFile.modules)

				u.Path = path.Join(rootPath, advFile.updateinfo)
				uinfo, err := c.fetchSecurityAdvisory(u.String())
				if err != nil {
					return xerrors.Errorf("failed to fetch updateInfo: %w", err)
				}

				modules := map[string]ModuleInfo{}
				if advFile.modules != "" {
					u.Path = path.Join(rootPath, advFile.modules)
					modules, err = c.fetchModulesFromYaml(u.String())
					if err != nil {
						return xerrors.Errorf("failed to fetch modules info: %w", err)
					}
				}

				if err := extractModulesToUpdateInfo(uinfo, modules); err != nil {
					return xerrors.Errorf("failed to extract modules to updateinfo: %w", err)
				}

				for _, adv1 := range uinfo.Advisories {
					adv2, ok := advisories[adv1.ID]
					if ok {
						if adv1.Updated.Date != adv2.Updated.Date {
							advisories[adv1.ID] = adv1
						} else if adv1.Issued.Date != adv2.Issued.Date {
							advisories[adv1.ID] = adv1
						} else if len(adv2.PkgLists) == 0 {
							advisories[adv1.ID] = adv1
						}
					} else {
						advisories[adv1.ID] = adv1
					}
				}
			}
		}
	}

	advPerYear := map[string][]Advisory{}
	for _, rlsa := range advisories {
		y := strings.Split(strings.TrimPrefix(rlsa.ID, "RLSA-"), ":")[0]
		advPerYear[y] = append(advPerYear[y], rlsa)
	}

	for year, advs := range advPerYear {
		log.Printf("Write Errata for Rocky Linux %s %s %s %s", majorVer, repo, arch, year)

		if err := os.MkdirAll(filepath.Join(dirPath, year), os.ModePerm); err != nil {
			return xerrors.Errorf("failed to mkdir: %w", err)
		}

		bar := pb.StartNew(len(advs))
		for _, adv := range advs {
			jsonPath := filepath.Join(dirPath, year, fmt.Sprintf("%s.json", adv.ID))
			if err := utils.Write(jsonPath, adv); err != nil {
				return xerrors.Errorf("failed to write Rocky Linux CVE details: %w", err)
			}
			bar.Increment()
		}
		bar.Finish()
	}

	return nil
}

type advisoryFile struct {
	updateinfo string
	modules    string
}

var repodataPattern = regexp.MustCompile(`^<a\shref="(.*-(?:modules\.yaml\.(?:xz|gz)|updateinfo\.xml\.gz))">.*</a>\s(\d{2}-(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-\d{4}\s\d{2}:\d{2}).*$`)

func (c Config) fetchAdvisoryFiles(repodataURL string) ([]advisoryFile, error) {
	res, err := utils.FetchURL(repodataURL, "", c.retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch %s: %w", repodataURL, err)
	}

	type fileinfo struct {
		name string
		date time.Time
	}

	uinfos := []fileinfo{}
	modules := []fileinfo{}
	scanner := bufio.NewScanner(bytes.NewBuffer(res))
	for scanner.Scan() {
		match := repodataPattern.FindStringSubmatch(scanner.Text())
		if len(match) != 3 {
			continue
		}
		t, err := time.Parse("02-Jan-2006 15:04", match[2])
		if err != nil {
			return nil, xerrors.Errorf("failed to parse repodata html time: %w", err)
		}
		finfo := fileinfo{
			name: match[1],
			date: t,
		}
		if strings.HasSuffix(finfo.name, "-updateinfo.xml.gz") {
			uinfos = append(uinfos, finfo)
		} else {
			modules = append(modules, finfo)
		}
	}
	sort.Slice(uinfos, func(i, j int) bool { return uinfos[i].date.Before(uinfos[j].date) })
	sort.Slice(modules, func(i, j int) bool { return modules[i].date.Before(modules[j].date) })

	advFiles := []advisoryFile{}
	latestModuleIdx := 0
	for _, uinfo := range uinfos {
		advFile := advisoryFile{
			updateinfo: uinfo.name,
		}
		// find the most recent modules as of the updateinfo date
		for i, module := range modules[latestModuleIdx:] {
			if module.date.After(uinfo.date) {
				if i > 0 {
					latestModuleIdx = latestModuleIdx + i - 1
				}
				break
			}
			advFile.modules = module.name
		}
		advFiles = append(advFiles, advFile)
	}
	return advFiles, nil
}

func (c Config) fetchSecurityAdvisory(url string) (*UpdateInfo, error) {
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

	advs := []Advisory{}
	for _, adv := range updateInfo.Advisories {
		if !strings.HasPrefix(adv.ID, "RLSA-") {
			continue
		}
		var cveIDs []string
		for _, ref := range adv.References {
			if ref.Type == "cve" {
				cveIDs = append(cveIDs, ref.ID)
			}
		}
		adv.CveIDs = cveIDs
		advs = append(advs, adv)
	}
	updateInfo.Advisories = advs
	return &updateInfo, nil
}

func (c Config) fetchModulesFromYaml(url string) (map[string]ModuleInfo, error) {
	res, err := utils.FetchURL(url, "", c.retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch modules: %w", err)
	}

	var r io.Reader
	switch ext := filepath.Ext(url)[1:]; ext {
	case "xz":
		r, err = xz.NewReader(bytes.NewBuffer(res))
		if err != nil {
			return nil, xerrors.Errorf("failed to decompress xz modules: %w", err)
		}
	case "gz":
		r, err = gzip.NewReader(bytes.NewBuffer(res))
		if err != nil {
			return nil, xerrors.Errorf("failed to decompress gzip modules: %w", err)
		}
	default:
		return nil, xerrors.Errorf("failed to decompress %s modules: unsupported extension", ext)
	}

	modules, err := parseModulemd(r)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse modulemd: %w", err)
	}

	return modules, nil
}

func parseModulemd(modulemdReader io.Reader) (map[string]ModuleInfo, error) {
	modules := map[string]ModuleInfo{}
	scanner := bufio.NewScanner(modulemdReader)
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
	// pkgToModuleStr: convert from package information to moduleStr
	pkgToModuleStr := convertToPkgToModuleStr(modules)

	missingModuleIDs := []string{}
	for i := range uinfo.Advisories {
		moduleStrToPkgs := convertToModuleStrToPkgs(uinfo.Advisories[i].Packages, pkgToModuleStr)
		if len(moduleStrToPkgs) == 0 {
			missingModuleIDs = append(missingModuleIDs, uinfo.Advisories[i].ID)
			continue
		}

		pkgLists := []PkgList{}
		for modularStr, pkgs := range moduleStrToPkgs {
			pkglist, err := buildPkgList(modules, modularStr, pkgs)
			if err != nil {
				return xerrors.Errorf("failed to build pkglist: %w", err)
			}
			pkgLists = append(pkgLists, pkglist)
		}

		uinfo.Advisories[i].PkgLists = pkgLists
		uinfo.Advisories[i].Packages = nil
	}

	if len(missingModuleIDs) > 0 {
		log.Printf("skip to extract module info to advisory because the affected package is not in modules.yaml. skip advisory IDs: %q", missingModuleIDs)
	}

	return nil
}

func convertToPkgToModuleStr(modules map[string]ModuleInfo) map[string]string {
	// pkgToModuleStr: convert from package information to moduleStr
	pkgToModuleStr := map[string]string{}
	for modularStr, module := range modules {
		for _, pkg := range module.Data.Artifacts.Rpms {
			pkgToModuleStr[pkg] = modularStr
		}
	}
	return pkgToModuleStr
}

func convertToModuleStrToPkgs(pkgs []Package, pkgToModuleStr map[string]string) map[string][]Package {
	// moduleStrToPkgs: convert from moduleStr to the relevant pkgs of the module (moduleStr is "" if it is not a module package)
	moduleStrToPkgs := map[string][]Package{}
	for _, pkg := range pkgs {
		moduleStr := ""
		if strings.Contains(pkg.Release, ".module+el") {
			var ok bool
			moduleStr, ok = pkgToModuleStr[pkg.String()]
			if !ok {
				return map[string][]Package{}
			}
		}
		moduleStrToPkgs[moduleStr] = append(moduleStrToPkgs[moduleStr], pkg)
	}
	return moduleStrToPkgs
}

func buildPkgList(modules map[string]ModuleInfo, modularStr string, pkgs []Package) (PkgList, error) {
	var module Module
	if modularStr != "" {
		minfo := modules[modularStr]
		module = Module{
			Stream:  minfo.Data.Stream,
			Name:    minfo.Data.Name,
			Version: minfo.Data.Version,
			Arch:    minfo.Data.Arch,
			Context: minfo.Data.Context,
		}

		pkgs = []Package{}
		for _, pkg := range minfo.Data.Artifacts.Rpms {
			name, ver, rel, epoch, arch, err := splitFileName(pkg)
			if err != nil {
				return PkgList{}, xerrors.Errorf("failed to split rpm filename: %w", err)
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
	}

	return PkgList{Packages: pkgs, Module: module}, nil
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
