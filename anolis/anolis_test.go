package anolis_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aquasecurity/vuln-list-update/anolis"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestConfig_Update(t *testing.T) {
	testCases := []struct {
		name             string
		appFs            afero.Fs
		xmlFileNames     map[string]string
		goldenFiles      map[string]string
		expectedErrorMsg string
	}{
		{
			name:  "happy path test",
			appFs: afero.NewMemMapFs(),
			xmlFileNames: map[string]string{
				"/anolis/anolis-7.oval.xml": "testdata/happy/anolis-7_els.oval.xml",
			},
			goldenFiles: map[string]string{
				"/tmp/anolis/7/2024/ANSA-2024-0788.json": "testdata/golden/7_els/2024/ANSA-2024:0784.json/ANSA-2024-0788.json",
			},
		},
		{
			name:  "sad path test",
			appFs: afero.NewMemMapFs(),
			xmlFileNames: map[string]string{
				"/anolis/anolis-7.oval.xml": "testdata/sad/anolis-7_els.oval.xml",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to decode Anolis OVAL XML",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				filePath, ok := tc.xmlFileNames[r.URL.Path]
				if !ok {
					http.NotFound(w, r)
					return
				}
				b, err := os.ReadFile(filePath)
				assert.NoError(t, err, tc.name)
				_, err = w.Write(b)
				assert.NoError(t, err, tc.name)
			}))
			defer ts.Close()

			urls := map[string]string{
				"7": ts.URL + "/anolis/anolis-7.oval.xml",
			}

			c := anolis.Config{
				VulnListDir: "/tmp",
				URLs:        urls,
				AppFs:       tc.appFs,
				Retry:       0,
			}

			err := c.Update()

			if tc.expectedErrorMsg != "" {
				assert.Contains(t, err.Error(), tc.expectedErrorMsg, tc.name)
				return
			} else {
				assert.NoError(t, err, tc.name)
			}

			// Validate generated files
			err = afero.Walk(c.AppFs, "/", func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}

				actual, err := afero.ReadFile(c.AppFs, path)
				assert.NoError(t, err, tc.name)

				goldenPath, ok := tc.goldenFiles[path]
				if !ok {
					return nil
				}

				expected, err := os.ReadFile(goldenPath)
				assert.NoError(t, err, tc.name)

				// Only print the diff if the test fails
				assert.Equal(t, expected, actual, tc.name)

				return nil
			})

			assert.NoError(t, err, tc.name)
		})
	}
}
