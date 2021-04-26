package govulndb

import (
	"encoding/json"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	vulndbURL   = "https://storage.googleapis.com/go-vulndb"
	vulndbDir   = "go"
	concurrency = 5
	wait        = 0
	retry       = 5
)

type options struct {
	url string
	dir string
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

type VulnDBSource struct {
	options
}

func NewVulnDB(opts ...option) VulnDBSource {
	o := &options{
		url: vulndbURL,
		dir: filepath.Join(utils.VulnListDir(), vulndbDir),
	}

	for _, opt := range opts {
		opt(o)
	}

	return VulnDBSource{options: *o}
}

func (c VulnDBSource) Update() error {
	log.Println("Fetching Go Vulnerability Database...")

	baseURL, err := url.Parse(c.url)
	if err != nil {
		return xerrors.Errorf("failed to parse baseURL for go-vulndb: %w", err)
	}

	// Parse index.json
	indexURL := *baseURL
	indexURL.Path = path.Join(indexURL.Path, "index.json")
	b, err := utils.FetchURL(indexURL.String(), "", retry)
	if err != nil {
		return xerrors.Errorf("failed to fetch go-vulndb index.json: %w", err)
	}

	var vulnerableModules map[string]string
	if err = json.Unmarshal(b, &vulnerableModules); err != nil {
		return xerrors.Errorf("failed to decode go-vulndb index.json response: %w", err)
	}

	// Parse package advisories
	log.Println("Saving Go Vulnerability Database...")
	bar := pb.StartNew(len(vulnerableModules))
	for moduleName := range vulnerableModules {
		pkgURL := *baseURL
		pkgURL.Path = path.Join(pkgURL.Path, moduleName+".json")

		res, err := utils.FetchURL(pkgURL.String(), "", retry)
		if err != nil {
			return xerrors.Errorf("unable to query %s advisory: err", moduleName, err)
		}

		var entries []Entry
		if err = json.Unmarshal(res, &entries); err != nil {
			return xerrors.Errorf("failed to decode go-vulndb response: %w", err)
		}

		if err = c.save(moduleName, entries); err != nil {
			return xerrors.Errorf("failed to save go-vulndb entries: %w", err)
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}

func (c VulnDBSource) save(moduleName string, entries []Entry) error {
	for _, entry := range entries {
		// Fill a module name
		entry.Module = moduleName

		pkgDir := filepath.Join(c.dir, moduleName)
		if err := os.MkdirAll(pkgDir, os.ModePerm); err != nil {
			return xerrors.Errorf("failed to create go-vulndb cve directory: %w", err)
		}

		filePath := filepath.Join(pkgDir, entry.ID+".json")
		if err := utils.Write(filePath, entry); err != nil {
			return xerrors.Errorf("failed to save go-vulndb detail: %w", err)
		}
	}
	return nil
}
