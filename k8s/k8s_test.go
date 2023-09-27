package k8s

import (
	"encoding/json"
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
	kvd, err := ParseVulnDBData(bi, map[string]string{})
	assert.NoError(t, err)
	err = validateCvesData(kvd.Cves)
	assert.NoError(t, err)
	gotVulnDB, err := json.Marshal(kvd.Cves)
	assert.NoError(t, err)
	wantVulnDB, err := os.ReadFile("./testdata/expected-vulndb.json")
	assert.NoError(t, err)
	assert.Equal(t, string(wantVulnDB), string(gotVulnDB))
}

func Test_TarToMap(t *testing.T) {
	t.Run("valid tar file with cve", func(t *testing.T) {
		r, err := os.Open("./testdata/fixture/cve_data.tgz")
		assert.NoError(t, err)
		tm, err := tarToMap(r)
		assert.NoError(t, err)
		assert.Equal(t, tm["CVE-2018-1002102"], "2018-11-26T11:07:36Z")
	})

	t.Run("no valid tar file without cve", func(t *testing.T) {
		r, err := os.Open("./testdata/fixture/no_cve_test.tgz")
		assert.NoError(t, err)
		tm, err := tarToMap(r)
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
