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

	"github.com/stretchr/testify/assert"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/amazon"
)

func TestConfig_Update(t *testing.T) {
	testCases := []struct {
		name              string
		repomdXmlFileName string
		gzipFileNames     map[string]string
		wantErr           error
		extras            map[string]string
	}{
		{
			name:              "happy path",
			repomdXmlFileName: "testdata/fixtures/repomd_valid.xml",
			gzipFileNames: map[string]string{
				"1":    "testdata/fixtures/updateinfo_1_item.xml.gz",
				"2":    "testdata/fixtures/updateinfo_2_items.xml.gz",
				"2022": "testdata/fixtures/updateinfo_AL2022.xml.gz",
				"2023": "testdata/fixtures/updateinfo_AL2023.xml.gz",
			},
			wantErr: nil,
			extras: map[string]string{
				"2": "testdata/fixtures/updateinfo_2_extras.xml.gz",
			},
		},
		{
			name:              "bad repomd XML response",
			repomdXmlFileName: "testdata/fixtures/repomd_invalid.xml",
			gzipFileNames: map[string]string{
				"2022": "testdata/fixtures/updateinfo_AL2022.xml.gz",
			},
			wantErr: xerrors.Errorf("failed to update security advisories of Amazon Linux 2022: %w", errors.New("failed to fetch security advisories from Amazon Linux Security Center: Failed to fetch updateinfo")),
		},
		{
			name:              "bad gzip data response",
			repomdXmlFileName: "testdata/fixtures/repomd_valid.xml",
			gzipFileNames: map[string]string{
				"2022": "testdata/fixtures/updateinfo_invalid.xml.gz",
			},
			wantErr: xerrors.Errorf("failed to update security advisories of Amazon Linux 2022: %w", errors.New("failed to fetch security advisories from Amazon Linux Security Center: Failed to fetch updateinfo")),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/mirror.list"):
					fmt.Println(r.URL.Path)
					pathSuffix := "core"
					if strings.Contains(r.URL.Path, "extras") {
						pathSuffix = "extras"
					}
					_, _ = fmt.Fprintf(w, "http://%s/%s/%s", r.Host, getVersionFromURL(r.URL.Path), pathSuffix)
				case strings.HasSuffix(r.URL.Path, "/repomd.xml"):
					repomd, _ := os.ReadFile(tc.repomdXmlFileName)
					_, _ = w.Write(repomd)
				case strings.HasSuffix(r.URL.Path, "extras.json"):
					extras, _ := os.ReadFile("testdata/fixtures/extras.json")
					_, _ = w.Write(extras)
				case strings.Contains(r.URL.Path, "updateinfo.xml.gz"):
					filename := tc.gzipFileNames[getVersionFromURL(r.URL.Path)]
					if strings.Contains(r.URL.Path, "extras") {
						filename = tc.extras[getVersionFromURL(r.URL.Path)]
					}
					buf, _ := os.ReadFile(filename)
					_, _ = w.Write(buf)
				default:
					assert.Fail(t, "bad URL requested: ", r.URL.Path, tc.name)
				}
			}))
			defer ts.Close()

			tmpDir := t.TempDir()

			mirrorList := map[string]string{}
			for key := range tc.gzipFileNames {
				mirrorList[key] = fmt.Sprintf("%s/%s/core/mirror.list", ts.URL, key)
			}
			extrasList := map[string]string{}
			for key := range tc.extras {
				extrasList[key] = fmt.Sprintf("%s/%s/extras.json", ts.URL, key)
			}

			ac := amazon.NewConfig(amazon.With(mirrorList, tmpDir, extrasList))

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
