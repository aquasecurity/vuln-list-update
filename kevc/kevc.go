package kevc

import (
	"encoding/json"
	"log"
	"path/filepath"

	"github.com/cheggaaa/pb"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	kevcURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	retry   = 5
	kevcDir = "kevc"
)

type Config struct {
	url   string
	dir   string
	retry int
}

type option func(config *Config)

func WithURL(url string) option {
	return func(c *Config) { c.url = url }
}

func WithDir(dir string) option {
	return func(c *Config) { c.dir = dir }
}

func WithRetry(retry int) option {
	return func(c *Config) { c.retry = retry }
}

func NewConfig(opts ...option) Config {
	c := Config{
		url:   kevcURL,
		dir:   filepath.Join(utils.VulnListDir(), kevcDir),
		retry: retry,
	}
	for _, opt := range opts {
		opt(&c)
	}

	return c
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
		if err := utils.SaveCVEPerYear(c.dir, vuln.CveID, vuln); err != nil {
			return xerrors.Errorf("failed to save KEVC per year: %w", err)
		}
		bar.Increment()
	}
	bar.Finish()
	return nil
}
