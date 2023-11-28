package nvd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/utils"
)

func TestUpdate(t *testing.T) {
	tests := []struct {
		name              string
		maxResultsPerPage int
		retry             int
		wantApiKey        string
		respFiles         map[string]string
		respStatus        int
		lastUpdatedTime   time.Time
		fakeTimeNow       time.Time
		wantFiles         []string
		wantError         string
	}{
		{
			name:              "happy path 1 page",
			maxResultsPerPage: 10,
			wantApiKey:        "test_api_key",
			lastUpdatedTime:   time.Date(2023, 11, 26, 0, 0, 0, 0, time.UTC),
			fakeTimeNow:       time.Date(2023, 11, 28, 0, 0, 0, 0, time.UTC),
			respFiles: map[string]string{
				"resultsPerPage=1&startIndex=0":  "testdata/fixtures/rootResp.json",
				"resultsPerPage=10&startIndex=0": "testdata/fixtures/respPageFull.json",
			},
			respStatus: 200,
			wantFiles: []string{
				filepath.Join("api", "2020", "CVE-2020-8167.json"),
				filepath.Join("api", "2021", "CVE-2021-22903.json"),
				filepath.Join("api", "2021", "CVE-2021-3881.json"),
				"last_updated.json",
			},
		},
		{
			name:              "happy path 1 page after reconnect",
			maxResultsPerPage: 10,
			wantApiKey:        "test_api_key",
			retry:             1,
			lastUpdatedTime:   time.Date(2023, 11, 26, 0, 0, 0, 0, time.UTC),
			fakeTimeNow:       time.Date(2023, 11, 28, 0, 0, 0, 0, time.UTC),
			respFiles: map[string]string{
				"resultsPerPage=1&startIndex=0":  "testdata/fixtures/rootResp.json",
				"resultsPerPage=10&startIndex=0": "testdata/fixtures/respPageFull.json",
			},
			respStatus: 403,
			wantFiles: []string{
				filepath.Join("api", "2020", "CVE-2020-8167.json"),
				filepath.Join("api", "2021", "CVE-2021-22903.json"),
				filepath.Join("api", "2021", "CVE-2021-3881.json"),
				"last_updated.json",
			},
		},
		{
			name:              "happy path 2 pages",
			maxResultsPerPage: 2,
			lastUpdatedTime:   time.Date(2023, 11, 26, 0, 0, 0, 0, time.UTC),
			fakeTimeNow:       time.Date(2023, 11, 28, 0, 0, 0, 0, time.UTC),
			respFiles: map[string]string{
				"resultsPerPage=1&startIndex=0": "testdata/fixtures/rootResp.json",
				"resultsPerPage=2&startIndex=0": "testdata/fixtures/respPage1.json",
				"resultsPerPage=2&startIndex=2": "testdata/fixtures/respPage2.json",
			},
			respStatus: 200,
			wantFiles: []string{
				filepath.Join("api", "2020", "CVE-2020-8167.json"),
				filepath.Join("api", "2021", "CVE-2021-22903.json"),
				filepath.Join("api", "2021", "CVE-2021-3881.json"),
				"last_updated.json",
			},
		},
		{
			name:              "503 error",
			maxResultsPerPage: 10,
			wantApiKey:        "test_api_key",
			lastUpdatedTime:   time.Date(2023, 11, 26, 0, 0, 0, 0, time.UTC),
			fakeTimeNow:       time.Date(2023, 11, 28, 0, 0, 0, 0, time.UTC),
			respStatus:        503,
			wantError:         "unable to fetch url",
		},
		{
			name:              "408 error",
			maxResultsPerPage: 10,
			wantApiKey:        "test_api_key",
			lastUpdatedTime:   time.Date(2023, 11, 26, 0, 0, 0, 0, time.UTC),
			fakeTimeNow:       time.Date(2023, 11, 28, 0, 0, 0, 0, time.UTC),
			respStatus:        408,
			wantError:         "unable to fetch url",
		},
		{
			name:              "502 error",
			maxResultsPerPage: 10,
			wantApiKey:        "test_api_key",
			lastUpdatedTime:   time.Date(2023, 11, 26, 0, 0, 0, 0, time.UTC),
			fakeTimeNow:       time.Date(2023, 11, 28, 0, 0, 0, 0, time.UTC),
			respStatus:        502,
			wantError:         "unable to fetch url",
		},
		{
			name:              "504 error",
			maxResultsPerPage: 10,
			wantApiKey:        "test_api_key",
			lastUpdatedTime:   time.Date(2023, 11, 26, 0, 0, 0, 0, time.UTC),
			fakeTimeNow:       time.Date(2023, 11, 28, 0, 0, 0, 0, time.UTC),
			respStatus:        504,
			wantError:         "unable to fetch url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantApiKey != "" {
				t.Setenv(apiKeyEnvName, tt.wantApiKey)
			}

			// overwrite vuln-list dir
			tmpDir := t.TempDir()
			savedVulnListDir := utils.VulnListDir()
			utils.SetVulnListDir(tmpDir)
			defer utils.SetVulnListDir(savedVulnListDir)

			// create last_updated.json file into temp dir
			err := utils.SetLastUpdatedDate("nvd", tt.lastUpdatedTime)
			require.NoError(t, err)

			respStatus := tt.respStatus
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(resp http.ResponseWriter, req *http.Request) {
				if respStatus != 200 {
					resp.WriteHeader(respStatus)
					// update respStatus update status after reconnection (if retry > 0)
					respStatus = 200
					return
				}

				if tt.wantApiKey != "" {
					gotApiKey := req.Header.Get("apiKey")
					require.Equal(t, tt.wantApiKey, gotApiKey)
				}

				var filePath string
				for params, path := range tt.respFiles {
					if strings.Contains(req.URL.String(), params) {
						filePath = path
						break
					}
				}
				if filePath == "" {
					t.Errorf("response files doesn't exist for %q", req.URL.String())
				}

				b, err := os.ReadFile(filePath)
				require.NoError(t, err)

				_, err = resp.Write(b)
				require.NoError(t, err)
			})
			ts := httptest.NewServer(mux)
			defer ts.Close()

			u := NewUpdater(WithBaseURL(ts.URL), WithMaxResultsPerPage(tt.maxResultsPerPage), WithRetry(tt.retry), WithLastModEndDate(tt.fakeTimeNow))
			err = u.Update()
			if tt.wantError != "" {
				require.ErrorContains(t, err, tt.wantError)
				return
			}

			require.NoError(t, err)
			for _, wantFile := range tt.wantFiles {
				got, err := os.ReadFile(filepath.Join(tmpDir, wantFile))
				require.NoError(t, err)

				want, err := os.ReadFile(filepath.Join("testdata", "golden", wantFile))
				require.NoError(t, err)

				require.JSONEq(t, string(want), string(got))
			}

		})
	}
}

func TestTimeIntervals(t *testing.T) {
	tests := []struct {
		name            string
		lastUpdatedTime time.Time
		fakeTimeNow     time.Time
		wantIntervals   []timeInterval
	}{
		{
			name:            "one interval",
			lastUpdatedTime: time.Date(2023, 11, 26, 0, 0, 0, 0, time.UTC),
			fakeTimeNow:     time.Date(2023, 11, 28, 0, 0, 0, 0, time.UTC),
			wantIntervals: []timeInterval{
				{
					lastModStartDate: "2023-11-26T00:00:00",
					lastModEndDate:   "2023-11-28T00:00:00",
				},
			},
		},
		{
			name:            "two intervals",
			lastUpdatedTime: time.Date(2023, 5, 28, 0, 0, 0, 0, time.UTC),
			fakeTimeNow:     time.Date(2023, 11, 28, 0, 0, 0, 0, time.UTC),
			wantIntervals: []timeInterval{
				{
					lastModStartDate: "2023-05-28T00:00:00",
					lastModEndDate:   "2023-09-25T00:00:00",
				},
				{
					lastModStartDate: "2023-09-25T00:00:00",
					lastModEndDate:   "2023-11-28T00:00:00",
				},
			},
		},
		{
			name:            "last_updated.json file doesn't exist",
			lastUpdatedTime: time.Unix(0, 0),
			fakeTimeNow:     time.Date(1970, 03, 01, 0, 0, 0, 0, time.UTC),
			wantIntervals: []timeInterval{
				{
					lastModStartDate: "1970-01-01T06:00:00",
					lastModEndDate:   "1970-03-01T00:00:00",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// overwrite vuln-list dir
			tmpDir := t.TempDir()
			savedVulnListDir := utils.VulnListDir()
			utils.SetVulnListDir(tmpDir)
			defer utils.SetVulnListDir(savedVulnListDir)

			if tt.lastUpdatedTime != time.Unix(0, 0) {
				// create last_updated.json file into temp dir
				err := utils.SetLastUpdatedDate("nvd", tt.lastUpdatedTime)
				assert.NoError(t, err)
			}

			gotIntervals, err := timeIntervals(tt.fakeTimeNow)
			assert.NoError(t, err)

			assert.Equal(t, tt.wantIntervals, gotIntervals)
		})
	}
}
