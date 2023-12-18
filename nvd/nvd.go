package nvd

import (
	"encoding/json"
	"io"
	"log/slog"
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
	retry             = 50
	url20             = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
	apiDir            = "api"
	nvdTimeFormat     = "2006-01-02T15:04:05"
	maxResultsPerPage = 2000
	retryAfter        = 30 * time.Second
	apiKeyEnvName     = "NVD_API_KEY"
)

type Option func(*Updater)

func WithLastModEndDate(lastModEndDate time.Time) Option {
	return func(u *Updater) {
		u.lastModEndDate = lastModEndDate
	}
}

func WithMaxResultsPerPage(maxResultsPerPage int) Option {
	return func(u *Updater) {
		u.maxResultsPerPage = maxResultsPerPage
	}
}

func WithBaseURL(url string) Option {
	return func(u *Updater) {
		u.baseURL = url
	}
}

func WithRetry(retry int) Option {
	return func(u *Updater) {
		u.retry = retry
	}
}

func WithRetryAfter(retryAfter time.Duration) Option {
	return func(u *Updater) {
		u.retryAfter = retryAfter
	}
}

type Updater struct {
	baseURL           string
	apiKey            string
	maxResultsPerPage int
	retry             int
	retryAfter        time.Duration
	lastModEndDate    time.Time // time.Now() by default
}

func NewUpdater(opts ...Option) *Updater {
	u := &Updater{
		baseURL:           url20,
		apiKey:            os.Getenv(apiKeyEnvName),
		maxResultsPerPage: maxResultsPerPage,
		retry:             retry,
		retryAfter:        retryAfter,
		lastModEndDate:    time.Now().UTC(),
	}

	for _, opt := range opts {
		opt(u)
	}
	return u
}

func (u Updater) Update() error {
	intervals, err := TimeIntervals(u.lastModEndDate)
	if err != nil {
		return xerrors.Errorf("unable to build time intervals: %w", err)
	}

	for _, interval := range intervals {
		slog.Info("Fetching NVD entries...", slog.String("start", interval.LastModStartDate),
			slog.String("end", interval.LastModEndDate))
		totalResults := 1 // Set a dummy value to start the loop
		for startIndex := 0; startIndex < totalResults; startIndex += u.maxResultsPerPage {
			if totalResults, err = u.saveEntry(interval, startIndex); err != nil {
				return xerrors.Errorf("unable to save entry CVEs for %q: %w", interval, err)
			}
			slog.Info("Fetched NVD entries", slog.Int("total", totalResults), slog.Int("start_index", startIndex))
		}
	}

	// Update last_updated.json at the end.
	if err = utils.SetLastUpdatedDate(apiDir, u.lastModEndDate); err != nil {
		return xerrors.Errorf("unable to update last_updated.json file: %w", err)
	}

	return nil
}

func (u Updater) saveEntry(interval TimeInterval, startIndex int) (int, error) {
	entryURL, err := urlWithParams(u.baseURL, startIndex, u.maxResultsPerPage, interval)
	if err != nil {
		return 0, xerrors.Errorf("unable to get url with query parameters: %w", err)
	}

	entry, err := u.fetchEntry(entryURL)
	if err != nil {
		return 0, xerrors.Errorf("unable to get entry for %q: %w", entryURL, err)
	}
	for _, vuln := range entry.Vulnerabilities {
		if err := utils.SaveCVEPerYear(filepath.Join(utils.VulnListDir(), apiDir), vuln.Cve.ID, vuln.Cve); err != nil {
			return 0, xerrors.Errorf("unable to write %s: %w", vuln.Cve.ID, err)
		}
	}
	return entry.TotalResults, nil
}

func (u Updater) fetchEntry(url string) (Entry, error) {
	var entry Entry
	r, err := u.fetchURL(url)
	if err != nil {
		return Entry{}, xerrors.Errorf("unable to fetch: %w", err)
	} else if r == nil {
		return Entry{}, xerrors.Errorf("unable to get entry from %q", url)
	}
	defer r.Close()

	if err = json.NewDecoder(r).Decode(&entry); err != nil {
		return Entry{}, xerrors.Errorf("unable to decode response for %q: %w", url, err)
	}
	return entry, nil
}

func (u Updater) fetchURL(url string) (io.ReadCloser, error) {
	var c http.Client
	for i := 0; i <= u.retry; i++ {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, xerrors.Errorf("unable to build request for %q: %w", url, err)
		}
		if u.apiKey != "" {
			req.Header.Set("apiKey", u.apiKey)
		}

		resp, err := c.Do(req)
		if err != nil {
			slog.Error("Response error. Try to get the entry again.", slog.String("error", err.Error()))
			continue
		}
		switch resp.StatusCode {
		case http.StatusForbidden:
			slog.Error("NVD rate limit. Wait to gain access.")
			// NVD limits:
			// Without API key: 5 requests / 30 seconds window
			// With API key: 50 requests / 30 seconds window
			time.Sleep(u.retryAfter)
			continue
		case http.StatusServiceUnavailable, http.StatusRequestTimeout, http.StatusBadGateway, http.StatusGatewayTimeout:
			slog.Error("NVD API is unstable. Try to fetch URL again.", slog.String("status_code", resp.Status))
			// NVD API works unstable
			time.Sleep(time.Duration(i) * time.Second)
			continue
		case http.StatusOK:
			return resp.Body, nil
		default:
			return nil, xerrors.Errorf("unexpected status code: %s", resp.Status)
		}

	}
	return nil, xerrors.Errorf("unable to fetch url. Retry limit exceeded.")
}

// TimeIntervals returns time intervals for NVD API
// NVD API doesn't allow to get more than 120 days per request.
// So we need to split the time range into intervals.
func TimeIntervals(endTime time.Time) ([]TimeInterval, error) {
	lastUpdatedDate, err := utils.GetLastUpdatedDate(apiDir)
	if err != nil {
		return nil, xerrors.Errorf("unable to get lastUpdatedDate: %w", err)
	}
	var intervals []TimeInterval
	for endTime.Sub(lastUpdatedDate).Hours()/24 > 120 {
		newLastUpdatedDate := lastUpdatedDate.Add(120 * 24 * time.Hour)
		intervals = append(intervals, TimeInterval{
			LastModStartDate: lastUpdatedDate.Format(nvdTimeFormat),
			LastModEndDate:   newLastUpdatedDate.Format(nvdTimeFormat),
		})
		lastUpdatedDate = newLastUpdatedDate
	}

	// fill latest interval
	intervals = append(intervals, TimeInterval{
		LastModStartDate: lastUpdatedDate.Format(nvdTimeFormat),
		LastModEndDate:   endTime.Format(nvdTimeFormat),
	})

	return intervals, nil
}

func urlWithParams(baseUrl string, startIndex, resultsPerPage int, interval TimeInterval) (string, error) {
	u, err := url.Parse(baseUrl)
	if err != nil {
		return "", xerrors.Errorf("unable to parse %q base url: %w", baseUrl, err)
	}
	q := u.Query()
	q.Set("lastModStartDate", interval.LastModStartDate)
	q.Set("lastModEndDate", interval.LastModEndDate)
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
