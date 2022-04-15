package alpine

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func Test_GetAllEOFDates(t *testing.T) {
	tests := []struct {
		name     string
		filepath string
		want     map[string]time.Time
	}{
		{
			name:     "happy path",
			filepath: "testdata/eol.html",
			want: map[string]time.Time{
				"3.15": time.Date(2023, 11, 01, 23, 59, 59, 0, time.UTC),
				"3.14": time.Date(2023, 05, 01, 23, 59, 59, 0, time.UTC),
				"edge": time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, test.filepath)
			}))
			defer ts.Close()

			dates, _ := getEOFDates(ts.URL, 1)

			assert.Equal(t, test.want, dates)
		})

	}
}
