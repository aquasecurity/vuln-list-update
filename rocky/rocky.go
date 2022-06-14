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
	urlFormat     = "%s/%s/%s/%s/os/"
	defaultRepos  = []string{"BaseOS", "AppStream", "extras"}
	defaultArches = []string{"x86_64", "aarch64"}

	minorReleaseVersionRegex = regexp.MustCompile(`^\d+.\d+[A-Za-z0-9-.]*/$`)
	oldReleaseBaseUrl        = "https://dl.rockylinux.org/vault/rocky"
	majorReleaseVersionRegex = regexp.MustCompile(`^\d+/$`)
	actualReleaseBaseUrl     = "https://download.rockylinux.org/pub/rocky"
)

type options struct {
	baseUrls  []string
	urlFormat string
	dir       string
	retry     int
	repos     []string
	arches    []string
}

type option func(*options)

func With(urlFormat, dir string, retry int, repos, arches, baseUrls []string) option {
	return func(opts *options) {
		opts.baseUrls = baseUrls
		opts.urlFormat = urlFormat
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
		baseUrls:  []string{actualReleaseBaseUrl, oldReleaseBaseUrl},
		urlFormat: urlFormat,
		dir:       filepath.Join(utils.VulnListDir(), rockyDir),
		retry:     retry,
		repos:     defaultRepos,
		arches:    defaultArches,
	}
	for _, opt := range opts {
		opt(o)
	}

	return Config{
		options: o,
	}
}

func (c Config) Update() error {
	// there are 2 different urls for actual and old releases
	// "8" is an alias of the latest release that doesn't contain old security advisories,
	// so we have to get all available minor releases like 8.5 and 8.6 so that we can have all the advisories.
	for _, baseUrl := range c.baseUrls {
		reg := minorReleaseVersionRegex
		if baseUrl == actualReleaseBaseUrl {
			reg = majorReleaseVersionRegex
		}
		releases, err := c.getReleasesList(reg, baseUrl)
		if err != nil {
			return xerrors.Errorf("failed to get a list of Rocky Linux releases: %w", err)
		}
		for _, release := range releases {
			for _, repo := range c.repos {
				for _, arch := range c.arches {
					log.Printf("Fetching Rocky Linux %s %s %s data...", release, repo, arch)
					if err = c.update(release, repo, arch, baseUrl); err != nil {
						return xerrors.Errorf("failed to update security advisories of Rocky Linux %s %s %s: %w", release, repo, arch, err)
					}
				}
			}
		}
	}
	return nil
}

func (c Config) update(release, repo, arch, baseUrl string) error {
	dirPath := filepath.Join(c.dir, release, repo, arch)
	log.Printf("Remove Rocky Linux %s %s %s directory %s", release, repo, arch, dirPath)
	if err := os.RemoveAll(dirPath); err != nil {
		return xerrors.Errorf("failed to remove Rocky Linux %s %s %s directory: %w", release, repo, arch, err)
	}
	if err := os.MkdirAll(dirPath, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}

	u, err := url.Parse(fmt.Sprintf(c.urlFormat, baseUrl, release, repo, arch))
	if err != nil {
		return xerrors.Errorf("failed to parse root url: %w", err)
	}
	rootPath := u.Path
	u.Path = path.Join(rootPath, "repodata/repomd.xml")
	updateInfoPath, err := c.fetchUpdateInfoPath(u.String())
	if err != nil {
		if errors.Is(err, ErrorNoUpdateInfoField) {
			log.Printf("skip repository because updateinfo field is not in repomd.xml: %s", err)
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

		if err = os.MkdirAll(filepath.Join(dirPath, year), os.ModePerm); err != nil {
			return xerrors.Errorf("failed to mkdir: %w", err)
		}

		bar := pb.StartNew(len(errata))
		for _, erratum := range errata {
			jsonPath := filepath.Join(dirPath, year, fmt.Sprintf("%s.json", erratum.ID))
			if err = utils.Write(jsonPath, erratum); err != nil {
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
	if err = xml.NewDecoder(bytes.NewBuffer(res)).Decode(&repoMd); err != nil {
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
	if err = xml.NewDecoder(r).Decode(&updateInfo); err != nil {
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

func (c Config) getReleasesList(reg *regexp.Regexp, baseUrl string) ([]string, error) {
	b, err := utils.FetchURL(baseUrl, "", c.retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to get list of releases: %w", err)
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(b))
	if err != nil {
		return nil, xerrors.Errorf("failed to read list of releases: %w", err)
	}

	var releases []string
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		if release := reg.FindString(s.Text()); release != "" {
			releases = append(releases, strings.TrimSuffix(release, "/"))
		}
	})

	if len(releases) == 0 {
		return nil, xerrors.Errorf("failed to get list of releases: list is empty")
	}
	return releases, nil
}
