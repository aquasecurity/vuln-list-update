package cvrf

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCVECvrfScoreSets(t *testing.T) {
	b, err := os.ReadFile("testdata/cvrf-cve-CVE-2014-6271.xml")
	require.NoError(t, err)
	ss, err := parseCVECvrfScoreSets(b)
	require.NoError(t, err)
	require.Len(t, ss, 2)
	assert.Equal(t, "5.1", ss[0].BaseScore)
	assert.Equal(t, "AV:N/AC:H/Au:N/C:P/I:P/A:P", ss[0].Vector)
	assert.Equal(t, "9.8", ss[1].BaseScore)
	assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", ss[1].Vector)
}
