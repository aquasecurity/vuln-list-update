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
	var bi K8sCVE
	err = json.Unmarshal(b, &bi)
	assert.NoError(t, err)
	kvd, err := ParseVulnDBData(bi)
	assert.NoError(t, err)
	err = validateCvesData(kvd.Cves)
	assert.NoError(t, err)
	gotVulnDB, err := json.Marshal(kvd.Cves)
	assert.NoError(t, err)
	//	os.WriteFile("./testdata/expected-vulndb.json", gotVulnDB, 0644)
	wantVulnDB, err := os.ReadFile("./testdata/expected-vulndb.json")
	assert.NoError(t, err)
	assert.Equal(t, string(wantVulnDB), string(gotVulnDB))
}
