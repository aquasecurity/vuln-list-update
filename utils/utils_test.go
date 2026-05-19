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

func TestFetchConcurrently_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1 * time.Second)
		w.Write([]byte("data"))
	}))
	defer srv.Close()

	urls := []string{srv.URL, srv.URL, srv.URL}

	// should not panic when timeout fires before workers finish
	require.NotPanics(t, func() {
		_, err := utils.FetchConcurrently(urls, 2, 0, 0, 100*time.Millisecond)
		assert.Error(t, err)
	})
}

func TestFetchConcurrently_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	urls := []string{srv.URL, srv.URL, srv.URL}

	responses, err := utils.FetchConcurrently(urls, 2, 0, 0, 10*time.Second)
	require.NoError(t, err)
	assert.Len(t, responses, 3)
	for _, r := range responses {
		assert.Equal(t, []byte("ok"), r)
	}
}
