package nvd

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
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
		lastModEndDate:    time.Now().UTC(),
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
		var totalResults int
		// startIndex for 1st request == 0
		totalResults, err = u.saveEntry(interval, 0)
		if err != nil {
			return xerrors.Errorf("unable to save entry CVEs for %q: %w", interval, err)
		}

		// if there are more records than maxResultsPerPage
		// check next records page by page (first page is saved above)
		for startIndex := u.maxResultsPerPage; startIndex < totalResults; startIndex += u.maxResultsPerPage {
			_, err = u.saveEntry(interval, startIndex)
			if err != nil {
				return xerrors.Errorf("unable to save entry CVEs for: %s", interval)
			}
		}
	}

	return nil
}

func (u Updater) saveEntry(interval timeInterval, startIndex int) (int, error) {
	entryURL, err := urlWithParams(u.baseURL, startIndex, u.maxResultsPerPage, interval)
	if err != nil {
		return 0, xerrors.Errorf("unable to get url with query parameters: %w", err)
	}

	var entry Entry
	entry, err = u.getEntry(entryURL)
	if err != nil {
		return 0, xerrors.Errorf("unable to get entry for %q: %w", entryURL, err)
	}
	if err = save(entry, interval.lastModEndDate); err != nil {
		return 0, xerrors.Errorf("unable to save entry: %w", err)
	}
	return entry.TotalResults, nil
}

func save(entry Entry, lastModEndDate string) error {
	for _, cve := range entry.Vulnerabilities {
		if err := utils.SaveCVEPerYear(filepath.Join(utils.VulnListDir(), apiDir), cve.Cve.ID, cve); err != nil {
			return xerrors.Errorf("unable to write %s: %w", cve.Cve.ID, err)
		}
	}
	// we need to save LastModEndDate to avoid saving wrong time if we get errors when saving all CVEs (first run)
	// after this we can switch to entry.Timestamp
	timestamp, err := time.Parse(nvdTimeFormat, lastModEndDate)
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

func (u Updater) getEntry(url string) (Entry, error) {
	var entry Entry
	r, err := fetchURL(url, u.apiKey, u.retry)

	if err != nil {
		return entry, xerrors.Errorf("unable to fetch: %w", err)
	}
	defer r.Close()

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
	for i := 0; i <= retry; i++ {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, xerrors.Errorf("unable to build request for %q: %w", url, err)
		}
		if apiKey != "" {
			req.Header.Set("apiKey", apiKey)
		}

		resp, err := c.Do(req)
		if err != nil {
			log.Printf("Response error: %s. Try to get Entry again", err)
			continue
		}
		switch resp.StatusCode {
		case http.StatusForbidden:
			log.Println("NVD rate limit. Waiting to gain access")
			// NVD limits:
			// Without API key: 5 requests / 30 seconds window
			// With API key: 50 requests / 30 seconds window
			time.Sleep(30 * time.Second)
			continue
		case http.StatusServiceUnavailable, http.StatusRequestTimeout, http.StatusBadGateway, http.StatusGatewayTimeout:
			log.Printf("NVD API is unstable: %s. Try to fetch URL again", resp.Status)
			// NVD API works unstable
			time.Sleep(1 * time.Second)
			continue
		case http.StatusOK:
			return resp.Body, nil
		default:
			return nil, xerrors.Errorf("unexpected status code: %s", resp.Status)
		}

	}
	return nil, xerrors.Errorf("unable to fetch url")
}

// 120 days is  maximum time range for the NVD API:
// `The maximum allowed range when using any date range options is 120 consecutive days.`
// timeIntervals divides time into intervals of 120 days
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
	if err != nil {
		return "", xerrors.Errorf("unable to decode query params: %w", err)
	}
	u.RawQuery = decoded
	return u.String(), nil
}
