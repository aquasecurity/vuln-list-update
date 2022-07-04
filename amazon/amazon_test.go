package amazon_test

import (
	"errors"
	"fmt"
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

func TestConfig_Update(t *testing.T) {
	testCases := []struct {
		name                 string
		repomdXmlFileName    string
		releasemdXmlFileName string
		gzipFileNames        map[string]string
		wantErr              error
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
			wantErr: nil,
		},
		{
			name:                 "bad repomd XML response",
			repomdXmlFileName:    "testdata/fixtures/repomd_invalid.xml",
			releasemdXmlFileName: "testdata/fixtures/releasemd_valid.xml",
			wantErr:              xerrors.Errorf("failed to update security advisories of Amazon Linux 2022: %w", errors.New("failed to fetch security advisories from Amazon Linux Security Center: Failed to fetch updateinfo")),
		},
		{
			name:                 "bad releasemd XML response",
			releasemdXmlFileName: "testdata/fixtures/releasemd_invalid.xml",
			wantErr:              xerrors.Errorf("failed to fetch mirror list of Amazon Linux 2022: list of Amazon Linux releases is empty"),
		},
		{
			name:                 "bad gzip data response",
			repomdXmlFileName:    "testdata/fixtures/repomd_valid.xml",
			releasemdXmlFileName: "testdata/fixtures/releasemd_valid.xml",
			gzipFileNames: map[string]string{
				"1": "testdata/fixtures/updateinfo_invalid.xml.gz",
			},
			wantErr: xerrors.Errorf("failed to update security advisories of Amazon Linux 1: %w", errors.New("failed to fetch security advisories from Amazon Linux Security Center: Failed to fetch updateinfo")),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/releasemd.xml"):
					buf, _ := os.ReadFile(tc.releasemdXmlFileName)
					_, _ = w.Write(buf)
				case strings.HasPrefix(r.URL.Path, "/2022/2022"):
					// Check if the latest release is properly taken
					assert.Equal(t, r.URL.Path, "/2022/2022.0.20220531/mirror.list")
					fallthrough
				case strings.HasSuffix(r.URL.Path, "/mirror.list"):
					fmt.Println(r.URL.Path)
					_, _ = fmt.Fprintf(w, "http://%s/%s", r.Host, getVersionFromURL(r.URL.Path))
				case strings.HasSuffix(r.URL.Path, "/repomd.xml"):
					repomd, _ := os.ReadFile(tc.repomdXmlFileName)
					_, _ = w.Write(repomd)
				case strings.Contains(r.URL.Path, "updateinfo.xml.gz"):
					buf, _ := os.ReadFile(tc.gzipFileNames[getVersionFromURL(r.URL.Path)])
					_, _ = w.Write(buf)
				default:
					assert.Fail(t, "bad URL requested: ", r.URL.Path, tc.name)
				}
			}))
			defer ts.Close()

			tmpDir := t.TempDir()

			mirrorList := map[string]string{}
			for key := range tc.gzipFileNames {
				if key != "2022" { // only for AL 1 and AL 2. AL 2022 gets mirror list from releasemd.xml
					mirrorList[key] = fmt.Sprintf("%s/%s/mirror.list", ts.URL, key)
				}
			}

			ac := amazon.NewConfig(amazon.With(mirrorList, tmpDir, ts.URL+"/releasemd.xml", ts.URL+"/2022/%s/mirror.list"))

			switch {
			case tc.wantErr != nil:
				assert.Equal(t, tc.wantErr.Error(), ac.Update().Error(), tc.name)
			default:
				assert.NoError(t, ac.Update(), tc.name)
			}

			err := filepath.Walk(tmpDir, func(path string, info os.FileInfo, errfp error) error {
				if info.IsDir() {
					return nil
				}
				filename := filepath.Base(path)
				golden := filepath.Join("testdata", filename+".golden")

				want, err := os.ReadFile(golden)
				assert.NoError(t, err, "failed to open the golden file")

				got, err := os.ReadFile(path)
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
