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
	maxResultsPerPage = 2000
	retryAfter        = 30 * time.Second
	apiKeyEnvName     = "NVD_API_KEY"

	// statusOriginTimeout is a non-standard Cloudflare status code (524) returned
	// when the origin server (NVD backend behind the proxy) does not respond in time.
	// There is no constant for it in net/http.
	statusOriginTimeout = 524
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

	var totalEntries int
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
		totalEntries += totalResults
	}

	// If NVD didn't return records for all intervals
	// we shouldn't update the last update as it might be a bug.
	if totalEntries == 0 {
		return nil
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
	body, err := u.fetchURL(url)
	if err != nil {
		return Entry{}, xerrors.Errorf("unable to fetch: %w", err)
	} else if body == nil {
		return Entry{}, xerrors.Errorf("unable to get entry from %q", url)
	}

	if err = json.Unmarshal(body, &entry); err != nil {
		return Entry{}, xerrors.Errorf("unable to decode response for %q: %w", url, err)
	}
	return entry, nil
}

func (u Updater) fetchURL(url string) ([]byte, error) {
	var c http.Client
	for i := 0; i <= u.retry; i++ {
		body, wait, err := u.doRequest(&c, url, i)
		if err != nil {
			return nil, err
		}
		// A nil body with a nil error means the request should be retried after `wait`.
		if body != nil {
			return body, nil
		}
		time.Sleep(wait)
	}
	return nil, xerrors.Errorf("unable to fetch url. Retry limit exceeded.")
}

// doRequest performs a single NVD request attempt and closes the response body
// before returning. It returns the response body on success. A nil body with a
// nil error means the request should be retried after waiting for `wait`.
func (u Updater) doRequest(c *http.Client, url string, attempt int) (body []byte, wait time.Duration, err error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, xerrors.Errorf("unable to build request for %q: %w", url, err)
	}
	if u.apiKey != "" {
		req.Header.Set("apiKey", u.apiKey)
	}

	resp, err := c.Do(req)
	if err != nil {
		slog.Error("Response error. Try to get the entry again.", slog.String("error", err.Error()))
		return nil, 0, nil
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusForbidden, http.StatusTooManyRequests:
		slog.Error("NVD rate limit. Wait to gain access.")
		ra := u.retryAfter
		// NVD returns the `Retry-After` header as 0.
		// But if they start setting a non-zero value, we can use that duration.
		if headerRetry := resp.Header.Get("Retry-After"); headerRetry != "0" {
			if hRetry, err := time.ParseDuration(headerRetry); err == nil {
				ra = hRetry
			}
		}
		// NVD limits:
		// Without API key: 5 requests / 30 seconds window
		// With API key: 50 requests / 30 seconds window
		return nil, ra, nil
	case http.StatusServiceUnavailable, http.StatusRequestTimeout, http.StatusBadGateway, http.StatusGatewayTimeout, statusOriginTimeout:
		slog.Error("NVD API is unstable. Try to fetch URL again.", slog.String("status_code", resp.Status))
		// NVD API works unstable
		return nil, time.Duration(attempt) * time.Second, nil
	case http.StatusOK:
		// Read the body here so that a transient error while reading the response
		// (e.g. HTTP/2 `INTERNAL_ERROR` when NVD aborts the stream mid-body) is
		// retried instead of failing the whole run.
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			slog.Error("Failed to read NVD response body. Try to fetch URL again.", slog.String("error", err.Error()))
			return nil, time.Duration(attempt) * time.Second, nil
		}
		return body, 0, nil
	default:
		return nil, 0, xerrors.Errorf("unexpected status code: %s", resp.Status)
	}
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
			LastModStartDate: lastUpdatedDate.Format(time.RFC3339),
			LastModEndDate:   newLastUpdatedDate.Format(time.RFC3339),
		})
		lastUpdatedDate = newLastUpdatedDate
	}

	// fill latest interval
	intervals = append(intervals, TimeInterval{
		LastModStartDate: lastUpdatedDate.Format(time.RFC3339),
		LastModEndDate:   endTime.Format(time.RFC3339),
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
