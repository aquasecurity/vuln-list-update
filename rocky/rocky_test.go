package rocky_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquasecurity/vuln-list-update/rocky"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"
)

func Test_Update(t *testing.T) {
	tests := []struct {
		name               string
		repomdFileName     string
		updateInfoFileName string
		expectedError      error
	}{
		{
			name:               "happy path",
			repomdFileName:     "testdata/fixtures/repomd_valid.xml",
			updateInfoFileName: "testdata/fixtures/updateinfo_valid.xml.gz",
			expectedError:      nil,
		},
		{
			name:           "bad repomd response",
			repomdFileName: "testdata/fixtures/repomd_invalid.xml",
			expectedError:  xerrors.Errorf("failed to update security advisories of Rocky Linux 8 BaseOS x86_64: %w", errors.New("failed to fetch updateInfo path from repomd.xml")),
		},
		{
			name:               "bad updateInfo response",
			repomdFileName:     "testdata/fixtures/repomd_valid.xml",
			updateInfoFileName: "testdata/fixtures/updateinfo_invalid.xml.gz",
			expectedError:      xerrors.Errorf("failed to update security advisories of Rocky Linux 8 BaseOS x86_64: %w", errors.New("failed to fetch updateInfo")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tsUpdateInfoURL := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "repomd.xml"):
					repomd, _ := os.ReadFile(tt.repomdFileName)
					_, _ = w.Write(repomd)
				case strings.HasSuffix(r.URL.Path, "updateinfo.xml.gz"):
					buf, _ := os.ReadFile(tt.updateInfoFileName)
					_, _ = w.Write(buf)
				default:
					assert.Fail(t, "bad URL requested: ", r.URL.Path, tt.name)
				}
			}))
			defer tsUpdateInfoURL.Close()

			tsMirrorListURL := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body := fmt.Sprintf(
					`# repo = rocky-BaseOS-8.4 arch = x86_64 country = JP country = ID country = KR country = CN country = GE country = TW country = AF country = KH country = PK country = HK country = CY \n
%s/pub/Linux/rocky-linux/8.4/BaseOS/x86_64/os/`, tsUpdateInfoURL.URL)
				_, _ = fmt.Fprintln(w, body)
			}))
			defer tsMirrorListURL.Close()

			dir := t.TempDir()
			rc := rocky.NewConfig(rocky.WithURL(tsMirrorListURL.URL+"/mirrorlist?release=%s&repo=%s-%s&arch=%s"), rocky.WithDir(dir), rocky.WithRetry(0), rocky.WithReleases([]string{"8"}), rocky.WithRepos([]string{"BaseOS"}), rocky.WithArches([]string{"x86_64"}))
			if err := rc.Update(); tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				return
			}

			err := filepath.Walk(dir, func(path string, info os.FileInfo, errfp error) error {
				if info.IsDir() {
					return nil
				}

				dir, file := filepath.Split(path)
				want, err := os.ReadFile(filepath.Join("testdata", "golden", filepath.Base(dir), file))
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
