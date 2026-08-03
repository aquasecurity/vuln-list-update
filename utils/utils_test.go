package utils_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/utils"
)

func TestFetchConcurrently(t *testing.T) {
	const body = "ok"

	tests := []struct {
		name        string
		serverDelay time.Duration
		timeout     time.Duration
		wantErr     bool
	}{
		{
			name:        "timeout fires before workers finish",
			serverDelay: 1 * time.Second,
			timeout:     100 * time.Millisecond,
			wantErr:     true,
		},
		{
			name:    "all urls fetched successfully",
			timeout: 10 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(tt.serverDelay)
				w.Write([]byte(body))
			}))
			defer srv.Close()

			urls := []string{srv.URL, srv.URL, srv.URL}

			var responses [][]byte
			var err error
			// should not panic even when the timeout fires before workers finish
			require.NotPanics(t, func() {
				responses, err = utils.FetchConcurrently(urls, 2, 0, 0, tt.timeout)
			})

			if tt.wantErr {
				assert.ErrorContains(t, err, "Timeout Fetching URL")
				return
			}

			require.NoError(t, err)
			assert.Len(t, responses, len(urls))
			for _, r := range responses {
				assert.Equal(t, []byte(body), r)
			}
		})
	}
}
