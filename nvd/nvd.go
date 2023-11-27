package nvd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/aquasecurity/vuln-list-update/utils"
	"golang.org/x/xerrors"
)

type NVD struct {
	CVEItems []interface{} `json:"CVE_Items"`
}

const (
	baseURL       = "https://nvd.nist.gov/feeds/json/cve/1.1"
	feedDir       = "feed"
	concurrency   = 5
	wait          = 0
	retry         = 5 // TODO move const to updater??
	url20         = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
	apiDir        = "../../testdata/api"
	nvdTimeFormat = "2006-01-02T15:04:05"
)

type options struct {
	apiDir         string
	baseURL        string
	apiKey         string
	lastModEndDate time.Time // time.Now() by default // TODO rename???
}

type option func(*options)

func WithLastModEndDate(lastModEndDate time.Time) option {
	return func(opts *options) {
		opts.lastModEndDate = lastModEndDate
	}
}

type Updater struct {
	*options
}

func NewUpdater(opts ...option) Updater {
	o := &options{
		apiDir:         apiDir,
		baseURL:        url20,
		apiKey:         os.Getenv("NVD_API_KEY"),
		lastModEndDate: time.Now(),
	}

	for _, opt := range opts {
		opt(o)
	}
	return Updater{
		options: o,
	}
}

func (updater Updater) Update() error {
	intervals, err := timeIntervals(updater.lastModEndDate)
	if err != nil {
		return xerrors.Errorf("unable to build time intervals: %w", err)
	}

	for _, interval := range intervals {
		var entry Entry // TODO rename???
		var rootURL string
		// save only 1 CVE for 1st fetch to find number of CVEs
		rootURL, err = urlWithParams(updater.baseURL, 0, 1, interval)

		entry, err = getEntryFromURL(rootURL, updater.apiKey, retry)
		if err != nil {
			return xerrors.Errorf("unable to get entry for %q: %w", rootURL, err)
		}

		// 2000 is max sire of response page
		for entry.StartIndex <= entry.TotalResults {
			var pageEntry Entry
			var pageURL string
			pageURL, err = urlWithParams(updater.baseURL, entry.StartIndex, 2000, interval)

			pageEntry, err = getEntryFromURL(pageURL, updater.apiKey, retry)
			if err != nil {
				return xerrors.Errorf("unable to get entry for %q: %w", pageURL, err)
			}
			if err = save(pageEntry); err != nil {
				return xerrors.Errorf("unable to save entry: %w", err)
			}
			entry.StartIndex += 2000
		}
	}

	return nil
}

func getEntryFromURL(url, apiKey string, retry int) (Entry, error) {
	var entry Entry
	for i := 0; i < retry; i++ {
		r, err := fetchURL(url, apiKey)
		if err != nil {
			return entry, xerrors.Errorf("unable to fetch: %w", err)
		}
		if r != nil {
			if err = json.NewDecoder(r).Decode(&entry); err != nil {
				return entry, xerrors.Errorf("unable to decode response for %q: %w", url, err)
			}
			return entry, nil
		}
	}
	return entry, xerrors.Errorf("unable to get entry from %q", url)
}

func fetchURL(url, apiKey string) (io.ReadCloser, error) {
	var c http.Client
	var resp *http.Response
	for i := 0; i < 50; i++ {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, xerrors.Errorf("unable to build request for %q", url, err)
		}
		if apiKey != "" {
			req.Header.Set("apiKey", apiKey)
		}

		resp, err = c.Do(req)
		if err != nil {
			continue
		}

		// TODO update logic for error codes
		if resp.StatusCode == http.StatusServiceUnavailable {
			time.Sleep(1 * time.Second)
			continue
		}
		if resp.StatusCode == http.StatusForbidden {
			time.Sleep(10 * time.Second)
			continue
		}
		if resp.StatusCode == http.StatusOK {
			return resp.Body, nil
		}
	}
	return nil, xerrors.Errorf("unable to get response")
}

func timeIntervals(endTime time.Time) ([]timeInterval, error) {
	//lastUpdatedDate, err := utils.GetLastUpdatedDate("nvd")
	//if err != nil {
	//	return nil, xerrors.Errorf("unable to get lastUpdatedDate: %w", err)
	//}
	lastUpdatedDate := time.Now().Add(-110 * 24 * time.Hour)
	var intervals []timeInterval
	for endTime.Sub(lastUpdatedDate).Hours()/24 > 120 {
		newLastUpdatedDate := lastUpdatedDate.Add(120 * 24 * time.Hour)
		intervals = append(intervals, timeInterval{
			lastModStartDate: lastUpdatedDate.Format(nvdTimeFormat),
			lastModEndDate:   newLastUpdatedDate.Format(nvdTimeFormat),
		})
		lastUpdatedDate = newLastUpdatedDate
	}

	// fill latest interval
	intervals = append(intervals, timeInterval{
		lastModStartDate: lastUpdatedDate.Format(nvdTimeFormat),
		lastModEndDate:   endTime.Format(nvdTimeFormat),
	})

	return intervals, nil
}

func save(entry Entry) error {
	for _, cve := range entry.Vulnerabilities {
		path := filepath.Join(apiDir, fmt.Sprintf("%s.json", cve.Cve.ID))
		if err := utils.Write(path, cve); err != nil {
			return xerrors.Errorf("unable to write %s: %w", cve.Cve.ID, err)
		}
	}
	return nil
}

func urlWithParams(baseUrl string, startIndex, resultsPerPage int, interval timeInterval) (string, error) {
	u, err := url.Parse(baseUrl)
	if err != nil {
		return "", xerrors.Errorf("unable to parse %q base url: %w", baseUrl, err)
	}
	q := u.Query()
	q.Set("lastModStartDate", interval.lastModStartDate)
	q.Set("lastModEndDate", interval.lastModEndDate)
	q.Set("startIndex", strconv.Itoa(startIndex))
	q.Set("resultsPerPage", strconv.Itoa(resultsPerPage))
	decoded, err := url.QueryUnescape(q.Encode()) // TODO refactor
	u.RawQuery = decoded
	return u.String(), nil
}
