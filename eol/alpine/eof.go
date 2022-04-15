package alpine

import (
	"bytes"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	eolAlpineFolder = "eol/alpine"
	eolAlpineFile   = "eol-alpine"
	eolAlpineUrl    = "https://alpinelinux.org/releases/"
	retry           = 5
)

type Config struct {
	vulnListDir string
	eolUrl      string
	retry       int
	appFs       afero.Fs
}

func NewConfig() Config {
	return Config{
		vulnListDir: utils.VulnListDir(),
		eolUrl:      eolAlpineUrl,
		retry:       retry,
		appFs:       afero.NewOsFs(),
	}
}

func (config Config) Update() error {
	dates, err := getEOFDates(config.eolUrl, config.retry)
	if err != nil {
		return err
	}

	err = config.save(dates)
	if err != nil {
		return err
	}

	return nil
}

func getEOFDates(eolUrl string, retry int) (map[string]time.Time, error) {
	eolDates := make(map[string]time.Time)

	log.Println("Fetching Alpine end of life dates...")
	b, err := utils.FetchURL(eolUrl, "", retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to get eol list: %w", err)
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(b))
	if err != nil {
		return nil, xerrors.Errorf("failed to read eol list: %w", err)
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

				// Move time to end of day
				date = d.Add(time.Hour*23 + time.Minute*59 + time.Second*59)
			}
		})
		eolDates[version] = date
	})

	// edge version doesn't have EOL. Add max date.
	eolDates["edge"] = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

	return eolDates, nil
}

func (config Config) save(dates map[string]time.Time) error {
	dir := filepath.Join(config.vulnListDir, eolAlpineFolder)
	if err := os.RemoveAll(dir); err != nil {
		return xerrors.Errorf("unable to remove github security advisory directory: %w", err)
	}
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}

	fileName := fmt.Sprintf("%s.json", eolAlpineFile)
	if err := utils.WriteJSON(config.appFs, dir, fileName, dates); err != nil {
		return xerrors.Errorf("failed to write %s under %s: %w", fileName, eolAlpineFolder, err)
	}
	return nil
}
