package alpine

import (
	"bytes"
	"github.com/PuerkitoBio/goquery"
	"github.com/aquasecurity/vuln-list-update/utils"
	"golang.org/x/xerrors"
	"log"
	"strings"
	"time"
)

const (
	eolUrl       = "https://alpinelinux.org/releases/"
	retryRequest = 1
)

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
