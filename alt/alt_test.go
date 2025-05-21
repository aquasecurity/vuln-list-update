package alt

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Update(t *testing.T) {
	testCases := []struct {
		name      string
		dir       string
		wantFiles int
		wantErr   string
	}{
		{
			name: "happy path",
			dir:  "testdata/happy",
		},
		{
			name:    "404",
			dir:     "testdata/missing-oval",
			wantErr: "failed to get ALT's OVAL branch archive: failed to fetch URL: HTTP error. status code: 404, url:",
		},
		{
			name:    "broken XML",
			dir:     "testdata/broken",
			wantErr: "failed to unmarshal ALT's OVAL xml: XML syntax error on line 4: element <cpe> closed by </cp>",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.FileServer(http.Dir(tc.dir)))
			defer ts.Close()

			tmpDir := "/tmp" // It is a virtual filesystem of afero.
			appFs := afero.NewMemMapFs()
			c := Config{
				VulnListDir:   tmpDir,
				BranchURL:     ts.URL + "/%s/oval_definitions.zip",
				BranchListURL: ts.URL + "/branches.json",
				AppFs:         appFs,
				Retry:         0,
			}

			err := c.Update()
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}

			require.NoError(t, err, tc.name)
			assert.NoError(t, err, tc.name)
		})
	}
}
