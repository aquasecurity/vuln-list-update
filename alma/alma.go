package alma

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	almaLinuxDir = "alma"
	urlFormat    = "https://errata.almalinux.org/%s/errata.json"
	retry        = 3
)

var (
	AlmaReleaseVersion = []string{"8", "9"}
)

type erratum struct {
	ID           OID         `json:"_id"`
	BsRepoID     OID         `json:"bs_repo_id"`
	UpdateinfoID string      `json:"updateinfo_id"`
	Description  string      `json:"description"`
	Fromstr      string      `json:"fromstr"`
	IssuedDate   Date        `json:"issued_date"`
	Pkglist      Pkglist     `json:"pkglist"`
	Pushcount    string      `json:"pushcount"`
	References   []Reference `json:"references"`
	Release      string      `json:"release"`
	Rights       string      `json:"rights"`
	Severity     string      `json:"severity"`
	Solution     string      `json:"solution"`
	Status       string      `json:"status"`
	Summary      string      `json:"summary"`
	Title        string      `json:"title"`
	Type         string      `json:"type"`
	UpdatedDate  Date        `json:"updated_date"`
	Version      string      `json:"version"`
}

type OID struct {
	OID string `json:"$oid,omitempty"`
}

type Date struct {
	Date int64 `json:"$date"`
}

type Pkglist struct {
	Name      string    `json:"name"`
	Shortname string    `json:"shortname"`
	Packages  []Package `json:"packages"`
	Module    Module    `json:"module"`
}

type Package struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	Release         string      `json:"release"`
	Epoch           string      `json:"epoch"`
	Arch            string      `json:"arch"`
	Src             string      `json:"src"`
	Filename        string      `json:"filename"`
	Sum             string      `json:"sum"`
	SumType         interface{} `json:"sum_type"`
	RebootSuggested int         `json:"reboot_suggested"`
}

type Module struct {
	Stream  string `json:"stream,omitempty"`
	Name    string `json:"name,omitempty"`
	Version int64  `json:"version,omitempty"`
	Arch    string `json:"arch,omitempty"`
	Context string `json:"context,omitempty"`
}

type Reference struct {
	Href  string `json:"href"`
	Type  string `json:"type"`
	ID    string `json:"id"`
	Title string `json:"title"`
}

type options struct {
	urls  map[string]string
	dir   string
	retry int
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

type Config struct {
	*options
}

func NewConfig(opts ...option) Config {
	urls := map[string]string{}
	for _, version := range AlmaReleaseVersion {
		urls[version] = fmt.Sprintf(urlFormat, version)
	}

	o := &options{
		urls:  urls,
		dir:   utils.VulnListDir(),
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
	for version, url := range c.urls {
		log.Printf("Fetching security advisories of AlmaLinux %s ...\n", version)
		if err := c.update(version, url); err != nil {
			return xerrors.Errorf("failed to update security advisories of AlmaLinux %s: %w", version, err)
		}
	}
	return nil
}

func (c Config) update(version, url string) error {
	dirPath := filepath.Join(c.dir, almaLinuxDir, version)
	log.Printf("Remove AlmaLinux %s directory %s\n", version, dirPath)
	if err := os.RemoveAll(dirPath); err != nil {
		return xerrors.Errorf("failed to remove AlmaLinux %s directory: %w", version, err)
	}
	if err := os.MkdirAll(dirPath, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}

	body, err := utils.FetchURL(url, "", c.retry)
	if err != nil {
		return xerrors.Errorf("failed to fetch security advisories from AlmaLinux: %w", err)
	}

	var errata []erratum
	if err := json.Unmarshal(body, &errata); err != nil {
		return xerrors.Errorf("failed to unmarshal json: %w", err)
	}

	secErrata := map[string][]erratum{}
	for _, erratum := range errata {
		if !strings.HasPrefix(erratum.UpdateinfoID, "ALSA-") {
			continue
		}

		y := strconv.Itoa(time.UnixMilli(erratum.IssuedDate.Date).Year())
		secErrata[y] = append(secErrata[y], erratum)
	}

	for year, errata := range secErrata {
		log.Printf("Write Errata for AlmaLinux %s %s\n", version, year)

		if err := os.MkdirAll(filepath.Join(dirPath, year), os.ModePerm); err != nil {
			return xerrors.Errorf("failed to mkdir: %w", err)
		}

		bar := pb.StartNew(len(errata))
		for _, erratum := range errata {
			filepath := filepath.Join(dirPath, year, fmt.Sprintf("%s.json", erratum.UpdateinfoID))
			if err := utils.Write(filepath, erratum); err != nil {
				return xerrors.Errorf("failed to write AlmaLinux CVE details: %w", err)
			}
			bar.Increment()
		}
		bar.Finish()
	}

	return nil
}
