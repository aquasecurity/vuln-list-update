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
		name                 string
		repomdXmlFileName    string
		releasemdXmlFileName string
		gzipFileNames        map[string]string
		expectedError        error
	}{
		{
			name:                 "happy path",
			repomdXmlFileName:    "testdata/fixtures/repomd_valid.xml",
			releasemdXmlFileName: "testdata/fixtures/releasemd_valid.xml",
			gzipFileNames: map[string]string{
				"1":    "testdata/fixtures/updateinfo_1_item.xml.gz",
				"2":    "testdata/fixtures/updateinfo_2_items.xml.gz",
				"2022": "testdata/fixtures/updateinfo_AL2022.xml.gz",
			},
			expectedError: nil,
		},
		{
			name:                 "bad repomd XML response",
			repomdXmlFileName:    "testdata/fixtures/repomd_invalid.xml",
			releasemdXmlFileName: "testdata/fixtures/releasemd_valid.xml",
			expectedError:        xerrors.Errorf("failed to update security advisories of Amazon Linux 2022: %w", errors.New("failed to fetch security advisories from Amazon Linux Security Center: Failed to fetch updateinfo")),
		},
		{
			name:                 "bad releasemd XML response",
			releasemdXmlFileName: "testdata/fixtures/releasemd_invalid.xml",
			expectedError:        xerrors.Errorf("failed to fetch mirror list of Amazon Linux 2022: list of Amazon Linux releases is empty"),
		},
		{
			name:                 "bad gzip data response",
			repomdXmlFileName:    "testdata/fixtures/repomd_valid.xml",
			releasemdXmlFileName: "testdata/fixtures/releasemd_valid.xml",
			gzipFileNames: map[string]string{
				"1": "testdata/fixtures/updateinfo_invalid.xml.gz",
			},
			expectedError: xerrors.Errorf("failed to update security advisories of Amazon Linux 1: %w", errors.New("failed to fetch security advisories from Amazon Linux Security Center: Failed to fetch updateinfo")),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tsUpdateInfoURL := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "repomd.xml"):
					repomd, _ := ioutil.ReadFile(tc.repomdXmlFileName)
					_, _ = w.Write(repomd)
				case strings.Contains(r.URL.Path, "updateinfo.xml.gz"):
					buf, _ := ioutil.ReadFile(tc.gzipFileNames[getVersionFromURL(r.URL.Path)])
					_, _ = w.Write(buf)
				default:
					assert.Fail(t, "bad URL requested: ", r.URL.Path, tc.name)
				}
			}))
			defer tsUpdateInfoURL.Close()

			tsMirrorListURL := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprintln(w, tsUpdateInfoURL.URL+"/"+getVersionFromURL(r.URL.Path))
			}))
			defer tsMirrorListURL.Close()

			tsReleasesURL := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				buf, _ := ioutil.ReadFile(tc.releasemdXmlFileName)
				_, _ = w.Write(buf)
			}))
			defer tsMirrorListURL.Close()

			dir, _ := ioutil.TempDir("", "amazon")
			defer os.RemoveAll(dir)

			mirrorList := map[string]string{}

			for key := range tc.gzipFileNames {
				if key != "2022" { // only for AL 1 and AL 2. Al 2022 get mirror list from fetchAmazonLinux2022MirrorList
					mirrorList[key] = tsMirrorListURL.URL + "/" + key
				}
			}

			ac := amazon.Config{
				LinuxMirrorListURI:        mirrorList,
				VulnListDir:               dir,
				AL2022ReleasemdURI:        tsReleasesURL.URL,
				AL2022MirrorListURIFormat: tsMirrorListURL.URL + "/2022/%s",
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
				assert.NoError(t, err, "failed to open the golden file")

				got, err := ioutil.ReadFile(path)
				assert.NoError(t, err, "failed to open the result file")

				assert.Equal(t, string(want), string(got))

				return nil
			})
			assert.Nil(t, err, "filepath walk error")
		})
	}
}

// urlPath like '/2022/repodata/repomd.xml'
func getVersionFromURL(urlPath string) string {
	v := strings.Split(urlPath, "/")
	return v[1]
}
