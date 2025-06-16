package eoldates_test

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/vuln-list-update/eoldates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "update golden files")

func Test_Update(t *testing.T) {
	tests := []struct {
		name        string
		eolDataFile string
		missedOSes  map[string][]eoldates.Release
		supportedOS []string
		wantFile    string
		wantErr     string
	}{
		{
			name:        "happy path",
			eolDataFile: "testdata/eoldata.json",
			supportedOS: []string{
				"alpine-linux",
				"ubuntu",
			},
			wantFile: "testdata/happy/eoldates.json",
		},
		{
			name:        "happy path with missed OSes",
			eolDataFile: "testdata/eoldata.json",
			supportedOS: []string{
				"alpine-linux",
				"mariner-linux",
				"ubuntu",
			},
			missedOSes: map[string][]eoldates.Release{
				"mariner-linux": {
					{
						Name:    "1.0",
						EOLFrom: "2023-07-31",
					},
				},
			},
			wantFile: "testdata/happy_with_missed_os/eoldates.json",
		},
		{
			name:        "happy path when missed OS overwrites date from EOLData",
			eolDataFile: "testdata/eoldata.json",
			supportedOS: []string{
				"alpine-linux",
				"ubuntu",
			},
			missedOSes: map[string][]eoldates.Release{
				"alpine-linux": {
					{
						Name:    "3.22",
						EOLFrom: "2999-01-01", // This date overwrites the one from EOLData
					},
				},
			},
			wantFile: "testdata/happy/eoldates.json",
		},
		{
			name:        "sad path - unable to fetch EOLData",
			supportedOS: []string{"ubuntu"},
			wantErr:     "unexpected status code: 404, body: 404 page not found",
		},
		{
			name:        "sad path - unable to unmarshal JSON",
			supportedOS: []string{"ubuntu"},
			eolDataFile: "testdata/sad_eoldata.json",
			wantErr:     "unable to parse JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.eolDataFile == "" {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, tt.eolDataFile)
			}))
			defer server.Close()

			c := eoldates.NewConfig(eoldates.WithURL(server.URL),
				eoldates.WithVulnListDir(tmpDir),
				eoldates.WithSupportedOSes(tt.supportedOS),
				eoldates.WithMissedOses(tt.missedOSes),
			)

			err := c.Update()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			filePath := filepath.Join(tmpDir, "eoldates", "eoldates.json")
			actual, err := os.ReadFile(filePath)
			require.NoError(t, err)

			if *update {
				err = os.WriteFile(tt.wantFile, actual, 0666)
				require.NoError(t, err, tt.wantFile)
			}

			expected, err := os.ReadFile(tt.wantFile)
			require.NoError(t, err)

			assert.JSONEq(t, string(expected), string(actual))
		})
	}
}
