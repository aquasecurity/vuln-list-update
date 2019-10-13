package amazon_test

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/amazon"
	"github.com/stretchr/testify/assert"
)

func Test_Update(t *testing.T) {
	testCases := []struct {
		name          string
		version       string
		xmlFileName   string
		gzipFileName  string
		expectedError error
	}{
		{
			name:          "1 item",
			version:       "1", // Amazon Linux 1
			xmlFileName:   "testdata/fixtures/repomd_valid.xml",
			gzipFileName:  "testdata/fixtures/updateinfo_1_item.xml.gz",
			expectedError: nil,
		},
		{
			name:          "2 items",
			version:       "2", // Amazon Linux 2
			xmlFileName:   "testdata/fixtures/repomd_valid.xml",
			gzipFileName:  "testdata/fixtures/updateinfo_2_items.xml.gz",
			expectedError: nil,
		},
		{
			name:          "bad XML response",
			version:       "1", // Amazon Linux 1
			xmlFileName:   "testdata/fixtures/repomd_invalid.xml",
			expectedError: xerrors.Errorf("failed to update security advisories of Amazon Linux 1: %w", errors.New("failed to fetch security advisories from Amazon Linux Security Center: Failed to fetch updateinfo")),
		},
		{
			name:          "bad gzip data response",
			version:       "2", // Amazon Linux 2
			xmlFileName:   "testdata/fixtures/repomd_valid.xml",
			gzipFileName:  "testdata/fixtures/updateinfo_invalid.xml.gz",
			expectedError: xerrors.Errorf("failed to update security advisories of Amazon Linux 2: %w", errors.New("failed to fetch security advisories from Amazon Linux Security Center: Failed to fetch updateinfo")),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tsUpdateInfoURL := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "repomd.xml"):
					repomd, _ := ioutil.ReadFile(tc.xmlFileName)
					_, _ = w.Write(repomd)
				case strings.Contains(r.URL.Path, "updateinfo.xml.gz"):
					buf, _ := ioutil.ReadFile(tc.gzipFileName)
					_, _ = w.Write(buf)
				default:
					assert.Fail(t, "bad URL requested: ", r.URL.Path, tc.name)
				}
			}))
			defer tsUpdateInfoURL.Close()

			tsMirrorListURL := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprintln(w, tsUpdateInfoURL.URL)
			}))
			defer tsMirrorListURL.Close()

			dir, _ := ioutil.TempDir("", "amazon")
			defer os.RemoveAll(dir)

			ac := amazon.Config{
				LinuxMirrorListURI: map[string]string{
					tc.version: tsMirrorListURL.URL,
				},
				VulnListDir: dir,
			}

			switch {
			case tc.expectedError != nil:
				assert.Equal(t, tc.expectedError.Error(), ac.Update().Error(), tc.name)
			default:
				assert.NoError(t, ac.Update(), tc.name)
			}

			err := filepath.Walk(dir, func(path string, info os.FileInfo, errfp error) error {
				if info.IsDir() {
					return nil
				}
				filename := filepath.Base(path)
				golden := filepath.Join("testdata", filename+".golden")

				want, err := ioutil.ReadFile(golden)
				assert.Nil(t, err, "failed to open the golden file")

				got, err := ioutil.ReadFile(path)
				assert.Nil(t, err, "failed to open the result file")

				assert.Equal(t, string(want), string(got))

				return nil
			})
			assert.Nil(t, err, "filepath walk error")
		})
	}
}
