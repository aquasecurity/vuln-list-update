package alpine

import (
	"bytes"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	eolutils "github.com/aquasecurity/vuln-list-update/eol/utils"
	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"
)

const (
	distName        = "alpine"
	eolAlpineFolder = "eol/alpine"
	eolAlpineFile   = "alpine.json"
	eolAlpineUrl    = "https://alpinelinux.org/releases/"
	retry           = 5
)

type Config struct {
	vulnListDir string
	eolUrl      string
	retry       int
	appFs       afero.Fs
}

type Option func(c *Config)

func WithVulnListDir(v string) Option {
	return func(c *Config) { c.vulnListDir = v }
}

func WithEolURL(v string) Option {
	return func(c *Config) { c.eolUrl = v }
}

func WithRetry(v int) Option {
	return func(c *Config) { c.retry = v }
}

func NewConfig(options ...Option) *Config {
	c := &Config{
		vulnListDir: utils.VulnListDir(),
		eolUrl:      eolAlpineUrl,
		retry:       retry,
		appFs:       afero.NewOsFs(),
	}
	for _, option := range options {
		option(c)
	}
	return c
}

func (c Config) Name() string {
	return distName
}

func (c Config) Update() error {
	dates, err := c.getEOFDates()
	if err != nil {
		return err
	}

	err = c.save(dates)
	if err != nil {
		return err
	}

	return nil
}

func (c Config) getEOFDates() (map[string]time.Time, error) {
	eolDates := make(map[string]time.Time)

	log.Println("Fetching Alpine end-of-life dates...")
	b, err := utils.FetchURL(c.eolUrl, "", c.retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to get list of end-of-life dates from url: %w", err)
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(b))
	if err != nil {
		return nil, xerrors.Errorf("failed to read list of end-of-life dates: %w", err)
	}

	doc.Find("tbody tr").Each(func(_ int, tr *goquery.Selection) {
		var version string
		var date time.Time

		tr.Find("td").Each(func(ix int, td *goquery.Selection) {
			switch ix {
			case 0:
				version = strings.TrimPrefix(td.Text(), "v") // remove 'v' prefix
			case 4:
				d, err := time.Parse("2006-01-02", td.Text())
				if err != nil {
					return
				}

				date = eolutils.MoveToEndOfDay(d)
			}
		})
		eolDates[version] = date
	})

	if len(eolDates) == 0 {
		return nil, xerrors.Errorf("List of end-of-life dates is empty.")
	}

	// edge version doesn't have EOL. Add max date.
	eolDates["edge"] = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

	return eolDates, nil
}

func (c Config) save(dates map[string]time.Time) error {
	dir := filepath.Join(c.vulnListDir, eolAlpineFolder)

	if err := utils.WriteJSON(c.appFs, dir, eolAlpineFile, dates); err != nil {
		return xerrors.Errorf("failed to write %s under %s: %w", eolAlpineFile, eolAlpineFolder, err)
	}
	return nil
}
