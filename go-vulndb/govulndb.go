package govulndb

import (
	"encoding/json"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	vulndbURL     = "https://storage.googleapis.com/go-vulndb"
	vulndbDir     = "go"
	retry         = 3
	notFoundError = "HTTP error. status code: 404"
)

type options struct {
	url   string
	dir   string
	retry int
}

type option func(*options)

func WithURL(url string) option {
	return func(opts *options) {
		opts.url = url
	}
}

func WithDir(dir string) option {
	return func(opts *options) {
		opts.dir = dir
	}
}

func WithRetry(retry int) option {
	return func(opts *options) {
		opts.retry = retry
	}
}

// VulnDB downloads Go Vulnerability Database and commits it to vuln-list.
// It is needed until OSV include module names.
// ref. https://github.com/golang/go/issues/50006
type VulnDB struct {
	options
}

func NewVulnDB(opts ...option) VulnDB {
	o := &options{
		url:   vulndbURL,
		dir:   filepath.Join(utils.VulnListDir(), vulndbDir),
		retry: retry,
	}

	for _, opt := range opts {
		opt(o)
	}

	return VulnDB{options: *o}
}

func (c VulnDB) Update() error {
	log.Println("Updating Go Vulnerability Database...")

	baseURL, err := url.Parse(c.url)
	if err != nil {
		return xerrors.Errorf("failed to parse base URL: %w", err)
	}

	if err = os.RemoveAll(c.dir); err != nil {
		return xerrors.Errorf("unable to remove old dir: %w", err)
	}

	modules, err := c.parseIndex(baseURL)
	if err != nil {
		return xerrors.Errorf("index error: %w", err)
	}

	for moduleName := range modules {
		entries, err := c.parseModuleEntries(baseURL, moduleName)
		if err != nil {
			return xerrors.Errorf("module entry error: %w", err)
		}

		for _, entry := range entries {
			entry.Module = moduleName
			filePath := filepath.Join(c.dir, moduleName, entry.ID+".json")
			if err = utils.Write(filePath, entry); err != nil {
				return xerrors.Errorf("file write error: %w", err)
			}
		}
	}

	return nil
}

func (c VulnDB) parseIndex(baseURL *url.URL) (map[string]string, error) {
	indexURL := *baseURL
	indexURL.Path = path.Join(indexURL.Path, "index.json")
	b, err := utils.FetchURL(indexURL.String(), "", c.retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch index.json: %w", err)
	}

	var modules map[string]string
	if err = json.Unmarshal(b, &modules); err != nil {
		return nil, xerrors.Errorf("json decode error: %w", err)
	}

	return modules, nil
}

func (c VulnDB) parseModuleEntries(baseURL *url.URL, moduleName string) ([]Entry, error) {
	pkgURL := *baseURL
	pkgURL.Path = path.Join(pkgURL.Path, moduleName+".json")

	res, err := utils.FetchURL(pkgURL.String(), "", c.retry)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			log.Printf("module %s not found", moduleName)
			return nil, nil
		}
		return nil, xerrors.Errorf("unable to query %s advisory: %w", moduleName, err)
	}

	var entries []Entry
	if err = json.Unmarshal(res, &entries); err != nil {
		return nil, xerrors.Errorf("failed to decode module entries: %w", err)
	}

	return entries, nil
}
