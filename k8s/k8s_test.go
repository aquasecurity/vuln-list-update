package k8s

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ParseVulneDB(t *testing.T) {
	b, err := os.ReadFile("./testdata/k8s-db.json")
	assert.NoError(t, err)
	var bi CVE
	err = json.Unmarshal(b, &bi)
	assert.NoError(t, err)

	ts := httptest.NewServer(http.FileServer(http.Dir("./testdata/mitreCVEs")))
	defer ts.Close()

	updater := NewUpdater(WithMitreURL(ts.URL))
	kvd, err := updater.ParseVulnDBData(bi, map[string]string{})
	assert.NoError(t, err)
	gotVulnDB, err := json.Marshal(kvd.Cves)
	assert.NoError(t, err)
	wantVulnDB, err := os.ReadFile("./testdata/expected-vulndb.json")
	assert.NoError(t, err)
	assert.Equal(t, string(wantVulnDB), string(gotVulnDB))
}

func Test_cveIDToModifiedMap(t *testing.T) {
	t.Run("valid folder with cve", func(t *testing.T) {
		tm, err := cveIDToModifiedMap("./testdata/happy/upstream")
		assert.NoError(t, err)
		assert.Equal(t, tm["CVE-2018-1002102"], "2018-11-26T11:07:36Z")
	})

	t.Run("not compatibale file", func(t *testing.T) {
		tm, err := cveIDToModifiedMap("./testdata/sad/upstream")
		assert.NoError(t, err)
		assert.True(t, len(tm) == 0)
	})

	t.Run("non existing folder", func(t *testing.T) {
		tm, err := cveIDToModifiedMap("./test")
		assert.NoError(t, err)
		assert.True(t, len(tm) == 0)
	})
}

func Test_OlderCve(t *testing.T) {
	tests := []struct {
		Name            string
		currentCveID    string
		currentModified string
		cveModified     map[string]string
		want            bool
	}{
		{Name: "match CVE but older Modified", currentCveID: "CVE-2018-1002102", currentModified: "2018-11-25T11:07:36Z", cveModified: map[string]string{"CVE-2018-1002102": "2018-11-26T11:07:36Z"}, want: true},
		{Name: "match CVE but older not Modified", currentCveID: "CVE-2018-1002102", currentModified: "2018-11-27T11:07:36Z", cveModified: map[string]string{"CVE-2018-1002102": "2018-11-26T11:07:36Z"}, want: false},
		{Name: "match CVE same time", currentCveID: "CVE-2018-1002102", currentModified: "2018-11-27T11:07:36Z", cveModified: map[string]string{"CVE-2018-1002102": "2018-11-27T11:07:36Z"}, want: true},
		{Name: "no existing cve", currentCveID: "CVE-2018-1002102", currentModified: "2018-11-27T11:07:36Z", cveModified: map[string]string{}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			got := olderCve(tt.currentCveID, tt.currentModified, tt.cveModified)
			assert.Equal(t, got, tt.want)

		})
	}
}
