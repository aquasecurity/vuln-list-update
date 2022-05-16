package kevc

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/cheggaaa/pb"
	"golang.org/x/xerrors"
	"log"
	"path/filepath"
	"strings"
)

const (
	kevcURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	retry   = 5
	kevcDir = "kevc"
)

type Updater struct {
	kevcURL     string
	vulnListDir string
	retry       int
}

type Config struct {
	*options
}

type option func(*options)

type options struct {
	url   string
	dir   string
	retry int
}

func WithURL(url string) option {
	return func(opts *options) { opts.url = url }
}

func WithDir(dir string) option {
	return func(opts *options) { opts.dir = dir }
}

func WithRetry(retry int) option {
	return func(opts *options) { opts.retry = retry }
}

func NewConfig(opts ...option) Config {
	o := &options{
		url:   kevcURL,
		dir:   filepath.Join(utils.VulnListDir(), kevcDir),
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
	log.Print("Fetching Known Exploited Vulnerabilities Catalog")

	res, err := utils.FetchURL(c.url, "", c.retry)
	if err != nil {
		return xerrors.Errorf("failed to fetch KEVC: %w", err)
	}
	kevc := KEVC{}
	if err := json.Unmarshal(res, &kevc); err != nil {
		return xerrors.Errorf("failed to KEVC json unmarshal error: %w", err)
	}
	if kevc.Count != len(kevc.Vulnerabilities) {
		return xerrors.Errorf("failed to Vulnerabilities count error: kevc.Count %d, kevc.Vulnerability length %d", kevc.Count, len(kevc.Vulnerabilities))
	}
	if err := c.update(kevc); err != nil {
		return xerrors.Errorf("failed to update KEVC: %w", err)
	}

	return nil
}

func (c Config) update(kevc KEVC) error {
	bar := pb.StartNew(kevc.Count)
	for _, vuln := range kevc.Vulnerabilities {
		if err := c.saveAdvisoryPerYear(vuln); err != nil {
			return xerrors.Errorf("failed to save advisory per year: %w", err)
		}
		bar.Increment()
	}
	bar.Finish()
	return nil
}

func (c Config) saveAdvisoryPerYear(vuln Vulnerability) error {
	if !strings.HasPrefix(vuln.CveID, "CVE") {
		log.Printf("discovered non-CVE-ID: %s", vuln.CveID)
		return nil
	}

	s := strings.Split(vuln.CveID, "-")
	if len(s) != 3 {
		log.Printf("invalid CVE-ID format: %s", vuln.CveID)
		return nil
	}

	yearDir := filepath.Join(c.dir, s[1])
	if err := utils.Write(filepath.Join(yearDir, fmt.Sprintf("%s.json", vuln.CveID)), vuln); err != nil {
		return xerrors.Errorf("unable to write a JSON file: %w", err)
	}
	return nil
}
