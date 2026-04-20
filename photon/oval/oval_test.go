package oval_test

import (
	"bytes"
	"compress/gzip"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/vuln-list-update/photon/oval"
)

var update = flag.Bool("update", false, "update golden files")

func TestConfig_Update(t *testing.T) {
	testCases := []struct {
		name             string
		appFs            afero.Fs
		xmlFileNames     map[string]string // URL path → XML file to serve gzip-compressed
		rawFileNames     map[string]string // URL path → file to serve as-is (for error cases)
		goldenFiles      map[string]string
		expectedErrorMsg string
	}{
		{
			name:  "positive test",
			appFs: afero.NewMemMapFs(),
			xmlFileNames: map[string]string{
				"/photon_oval_definitions/com.vmware.phsa-photon5.xml.gz": "testdata/photon5.xml",
			},
			goldenFiles: map[string]string{
				"/tmp/photon-oval/5.0/PHSA-2023-5.0-20.json":  "testdata/golden/photon-oval/5.0/PHSA-2023-5.0-20.json",
				"/tmp/photon-oval/5.0/PHSA-2024-5.0-347.json": "testdata/golden/photon-oval/5.0/PHSA-2024-5.0-347.json",
			},
		},
		{
			name:  "invalid filesystem write read only path",
			appFs: afero.NewReadOnlyFs(afero.NewOsFs()),
			xmlFileNames: map[string]string{
				"/photon_oval_definitions/com.vmware.phsa-photon5.xml.gz": "testdata/photon5.xml",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "unable to create a directory: operation not permitted",
		},
		{
			name:             "404",
			appFs:            afero.NewMemMapFs(),
			xmlFileNames:     map[string]string{},
			rawFileNames:     map[string]string{},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to fetch Photon OVAL: failed to fetch URL: HTTP error. status code: 404, url:",
		},
		{
			name:  "invalid gzip format",
			appFs: afero.NewMemMapFs(),
			rawFileNames: map[string]string{
				"/photon_oval_definitions/com.vmware.phsa-photon5.xml.gz": "testdata/invalid.txt",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to decompress Photon OVAL:",
		},
		{
			name:  "broken XML",
			appFs: afero.NewMemMapFs(),
			xmlFileNames: map[string]string{
				"/photon_oval_definitions/com.vmware.phsa-photon5.xml.gz": "testdata/broken_oval.xml",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to decode Photon OVAL XML:",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Serve gzip-compressed XML files
				if filePath, ok := tc.xmlFileNames[r.URL.Path]; ok {
					xmlData, err := os.ReadFile(filePath)
					assert.NoError(t, err, tc.name)

					var buf bytes.Buffer
					gz := gzip.NewWriter(&buf)
					_, err = gz.Write(xmlData)
					assert.NoError(t, err, tc.name)
					err = gz.Close()
					assert.NoError(t, err, tc.name)

					_, err = w.Write(buf.Bytes())
					assert.NoError(t, err, tc.name)
					return
				}

				// Serve raw files as-is (for testing gzip decode errors)
				if filePath, ok := tc.rawFileNames[r.URL.Path]; ok {
					b, err := os.ReadFile(filePath)
					assert.NoError(t, err, tc.name)
					_, err = w.Write(b)
					assert.NoError(t, err, tc.name)
					return
				}

				http.NotFound(w, r)
			}))
			defer ts.Close()

			// Use photon version 5 for URL targeting in tests
			urlFormat := ts.URL + "/photon_oval_definitions/com.vmware.phsa-photon%s.xml.gz"
			c := oval.Config{
				VulnListDir: "/tmp",
				URLFormat:   urlFormat,
				AppFs:       tc.appFs,
				Retry:       0,
			}

			// Wrap Update() to only process version "5" in tests
			err := c.UpdateVersion("5")
			switch {
			case tc.expectedErrorMsg != "":
				assert.Contains(t, err.Error(), tc.expectedErrorMsg, tc.name)
				return
			default:
				assert.NoError(t, err, tc.name)
			}

			fileCount := 0
			err = afero.Walk(c.AppFs, "/", func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				fileCount++

				actual, err := afero.ReadFile(c.AppFs, path)
				assert.NoError(t, err, tc.name)

				goldenPath, ok := tc.goldenFiles[path]
				assert.True(t, ok, tc.name)

				if *update {
					err = os.WriteFile(goldenPath, actual, 0666)
					assert.NoError(t, err, tc.name)
				}

				expected, err := os.ReadFile(goldenPath)
				assert.NoError(t, err, tc.name)

				assert.Equal(t, string(expected), string(actual), tc.name)

				return nil
			})
			assert.Equal(t, len(tc.goldenFiles), fileCount, tc.name)
			assert.NoError(t, err, tc.name)
		})
	}
}

// Additional test for PhsaIDFromRef corner cases
func TestPhsaIDFromRef(t *testing.T) {
	testCases := []struct {
		name        string
		refs        []oval.Reference
		issuedDate  string
		expectedID  string
		expectError bool
	}{
		{
			name: "valid single advisory",
			refs: []oval.Reference{
				{Source: "PHSA", ID: "PHSA:00001:5.0:20"},
				{Source: "CVE", ID: "CVE:00001:CVE-2023-2602"},
			},
			issuedDate: "2023-06-07",
			expectedID: "PHSA-2023-5.0-20",
		},
		{
			name: "valid multi-CVE advisory",
			refs: []oval.Reference{
				{Source: "PHSA", ID: "PHSA:00007:5.0:347"},
				{Source: "CVE", ID: "CVE:00007:CVE-2024-41184"},
			},
			issuedDate: "2024-08-15",
			expectedID: "PHSA-2024-5.0-347",
		},
		{
			name:        "no references",
			refs:        []oval.Reference{},
			issuedDate:  "2023-06-07",
			expectError: true,
		},
		{
			name:        "no PHSA source reference",
			refs:        []oval.Reference{{Source: "CVE", ID: "CVE:00001:CVE-2023-2602"}},
			issuedDate:  "2023-06-07",
			expectError: true,
		},
		{
			name:        "invalid ref_id format",
			refs:        []oval.Reference{{Source: "PHSA", ID: "PHSA:00001"}},
			issuedDate:  "2023-06-07",
			expectError: true,
		},
		{
			name:        "invalid issued date",
			refs:        []oval.Reference{{Source: "PHSA", ID: "PHSA:00001:5.0:20"}},
			issuedDate:  "",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := oval.PhsaIDFromRef(tc.refs, tc.issuedDate)
			if tc.expectError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedID, id)
		})
	}
}
