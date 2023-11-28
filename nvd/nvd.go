package nvd

import (
	"encoding/json"
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

const (
	retry             = 5
	url20             = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
	apiDir            = "api"
	nvdTimeFormat     = "2006-01-02T15:04:05"
	maxResultsPerPage = 2000
	apiKeyEnvName     = "NVD_API_KEY"
)

type options struct {
	baseURL           string
	apiKey            string
	maxResultsPerPage int
	retry             int
	lastModEndDate    time.Time // time.Now() by default
}

type option func(*options)

func WithLastModEndDate(lastModEndDate time.Time) option {
	return func(opts *options) {
		opts.lastModEndDate = lastModEndDate
	}
}

func WithMaxResultsPerPage(maxResultsPerPage int) option {
	return func(opts *options) {
		opts.maxResultsPerPage = maxResultsPerPage
	}
}

func WithBaseURL(url string) option {
	return func(opts *options) {
		opts.baseURL = url
	}
}

func WithRetry(retry int) option {
	return func(opts *options) {
		opts.retry = retry
	}
}

type Updater struct {
	*options
}

func NewUpdater(opts ...option) Updater {
	o := &options{
		baseURL:           url20,
		apiKey:            os.Getenv(apiKeyEnvName),
		maxResultsPerPage: maxResultsPerPage,
		retry:             retry,
		lastModEndDate:    time.Now(),
	}

	for _, opt := range opts {
		opt(o)
	}
	return Updater{
		options: o,
	}
}

func (u Updater) Update() error {
	intervals, err := timeIntervals(u.lastModEndDate)
	if err != nil {
		return xerrors.Errorf("unable to build time intervals: %w", err)
	}

	for _, interval := range intervals {
		var entry Entry
		var rootURL string
		// save only 1 CVE for 1st fetch to find number of CVEs
		rootURL, err = urlWithParams(u.baseURL, 0, 1, interval)

		entry, err = u.getEntryFromURL(rootURL)
		if err != nil {
			return xerrors.Errorf("unable to get entry for %q: %w", rootURL, err)
		}

		for entry.StartIndex <= entry.TotalResults {
			var pageEntry Entry
			var pageURL string
			pageURL, err = urlWithParams(u.baseURL, entry.StartIndex, u.maxResultsPerPage, interval)

			pageEntry, err = u.getEntryFromURL(pageURL)
			if err != nil {
				return xerrors.Errorf("unable to get entry for %q: %w", pageURL, err)
			}
			if err = save(pageEntry); err != nil {
				return xerrors.Errorf("unable to save entry: %w", err)
			}
			entry.StartIndex += u.maxResultsPerPage
		}
	}

	return nil
}

func save(entry Entry) error {
	for _, cve := range entry.Vulnerabilities {
		if err := utils.SaveCVEPerYear(filepath.Join(utils.VulnListDir(), apiDir), cve.Cve.ID, cve); err != nil {
			return xerrors.Errorf("unable to write %s: %w", cve.Cve.ID, err)
		}
	}
	timestamp, err := time.Parse(nvdTimeFormat, entry.Timestamp)
	if err != nil {
		return xerrors.Errorf("unable to parse timestamp: %w", err)
	}
	// update the Last_updated.json file after saving each entry
	// to avoid overwriting this entry if we fail to save the next entry
	err = utils.SetLastUpdatedDate("nvd", timestamp)
	if err != nil {
		return xerrors.Errorf("unable to save last_updated.json file: %w", err)
	}
	return nil
}

func (u Updater) getEntryFromURL(url string) (Entry, error) {
	var entry Entry
	r, err := fetchURL(url, u.apiKey, u.retry)
	if err != nil {
		return entry, xerrors.Errorf("unable to fetch: %w", err)
	}
	if r != nil {
		if err = json.NewDecoder(r).Decode(&entry); err != nil {
			return entry, xerrors.Errorf("unable to decode response for %q: %w", url, err)
		}
		return entry, nil
	}

	return entry, xerrors.Errorf("unable to get entry from %q", url)
}

func fetchURL(url, apiKey string, retry int) (io.ReadCloser, error) {
	var c http.Client
	var resp *http.Response
	for i := 0; i <= retry; i++ {
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
	lastUpdatedDate, err := utils.GetLastUpdatedDate("nvd")
	if err != nil {
		return nil, xerrors.Errorf("unable to get lastUpdatedDate: %w", err)
	}
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
	// NVD API doesn't work with escaped `:`
	// So we only need to escape `+` for `Z`:
	// https://nvd.nist.gov/developers/vulnerabilities:
	// `Please note, if a positive Z value is used (such as +01:00 for Central European Time) then the "+" should be encoded in the request as "%2B".`
	decoded, err := url.QueryUnescape(q.Encode())
	u.RawQuery = decoded
	return u.String(), nil
}
