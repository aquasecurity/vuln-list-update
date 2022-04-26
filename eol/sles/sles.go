package sles

import (
	"bytes"
	"log"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	eolutils "github.com/aquasecurity/vuln-list-update/eol/utils"
	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"
)

const (
	distName = "sles"
	dirPath  = "eol/sles"
	fileName = "sles.json"
	baseUrl  = "https://www.suse.com/lifecycle/"
	retry    = 5
)

var distVersionRegex = regexp.MustCompile(`SUSE Linux Enterprise Server (\d{2}( SP\d)?)`)

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
		eolUrl:      baseUrl,
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

	log.Println("Fetching SLES end-of-life dates...")
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
		var generalDate, ltssDate time.Time

		tr.Find("td").Each(func(ix int, td *goquery.Selection) {
			switch ix {
			case 0:
				v := distVersionRegex.FindStringSubmatch(td.Text())
				if len(v) > 0 {
					version = strings.ReplaceAll(strings.TrimPrefix(v[1], "SUSE Linux Enterprise Server "), " SP", ".")
				}
			case 2:
				text := td.Text()
				d, err := time.Parse("02 Jan 2006", text)
				if err != nil {
					d, err = time.Parse("02 January 2006", text) // https://www.suse.com/lifecycle/ can use full name of month
					if err != nil {
						return
					}
				}
				generalDate = eolutils.MoveToEndOfDay(d)
			case 3:
				text := strings.TrimSpace(td.Text())
				if text == "TBD" {
					ltssDate = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
				} else if text == "N/A" {
					ltssDate = generalDate
				} else {
					d, err := time.Parse("02 Jan 2006", text)
					if err != nil {
						d, err = time.Parse("02 January 2006", text) // https://www.suse.com/lifecycle/ can use full name of month
						if err != nil {
							return
						}
					}
					ltssDate = eolutils.MoveToEndOfDay(d)
				}

			}
		})
		if version != "" {
			eolDates[version] = ltssDate
		}
	})

	if len(eolDates) == 0 {
		return nil, xerrors.Errorf("List of end-of-life dates is empty.")
	}

	return eolDates, nil
}

func (c Config) save(dates map[string]time.Time) error {
	dir := filepath.Join(c.vulnListDir, dirPath)

	if err := utils.WriteJSON(c.appFs, dir, fileName, dates); err != nil {
		return xerrors.Errorf("failed to write %s under %s: %w", fileName, dirPath, err)
	}
	return nil
}
