package debian

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	eolutils "github.com/aquasecurity/vuln-list-update/eol/utils"
	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"
)

const (
	baseUrl  = "https://endoflife.date/api/%s.json"
	distName = "Debian"
	dirPath  = "eol/debian"
	fileName = "debian.json"
	retry    = 3
)

type options struct {
	url         string
	vulnListDir string
	retry       int
	appFs       afero.Fs
}

type option func(*options)

func WithURL(url string) option {
	return func(opts *options) { opts.url = url }
}

func WithVulnListDir(vulnListDir string) option {
	return func(opts *options) { opts.vulnListDir = vulnListDir }
}

func WithRetry(retry int) option {
	return func(opts *options) { opts.retry = retry }
}

type Config struct {
	*options
}

func NewConfig(opts ...option) Config {
	o := &options{
		url:         fmt.Sprintf(baseUrl, strings.ToLower(distName)),
		vulnListDir: utils.VulnListDir(),
		retry:       retry,
		appFs:       afero.NewOsFs(),
	}

	for _, opt := range opts {
		opt(o)
	}

	return Config{
		options: o,
	}
}

func (c Config) Name() string {
	return distName
}

func (c Config) Update() error {
	eolDates := map[string]time.Time{}

	cycles, err := eolutils.GetLifeCycles(distName, c.url, c.retry)
	if err != nil {
		return xerrors.Errorf("unable to get EOL dates from %s, err: %w ", c.url, err)
	}

	for _, cycle := range cycles {
		d, err := time.Parse("2006-01-02", cycle.Eol)
		if err != nil {
			return xerrors.Errorf("unable to parse %q date: %w", cycle.Eol, err)
		}
		eolDates[cycle.Cycle] = eolutils.MoveToEndOfDay(d)
	}

	// There is no release date for Debian 12 at this time. But it has a database of vulnerabilities.
	// We should to add it in eolDates.
	if len(eolDates) > 0 {
		eolDates["12"] = time.Date(3000, 1, 1, 23, 59, 59, 0, time.UTC)
	}

	return c.save(eolDates)
}

func (c Config) save(dates map[string]time.Time) error {
	dir := filepath.Join(c.vulnListDir, dirPath)

	if err := utils.WriteJSON(c.appFs, dir, fileName, dates); err != nil {
		return xerrors.Errorf("failed to write %s under %s: %w", fileName, dirPath, err)
	}
	return nil
}
