package rocky_test

import (
	"errors"
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
			repomdFileName:     "repomd_valid.xml",
			updateInfoFileName: "updateinfo_valid.xml.gz",
			expectedError:      nil,
		},
		{
			name:           "bad repomd response",
			repomdFileName: "repomd_invalid.xml",
			expectedError:  xerrors.Errorf("failed to update security advisories of Rocky Linux 8 BaseOS x86_64: %w", errors.New("failed to fetch updateInfo path from repomd.xml")),
		},
		{
			name:               "bad updateInfo response",
			repomdFileName:     "repomd_valid.xml",
			updateInfoFileName: "updateinfo_invalid.xml.gz",
			expectedError:      xerrors.Errorf("failed to update security advisories of Rocky Linux 8 BaseOS x86_64: %w", errors.New("failed to fetch updateInfo")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tsUpdateInfoURL := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/pub/rocky/8/BaseOS/x86_64/os/repodata/") {
					switch {
					case strings.HasSuffix(r.URL.Path, "repomd.xml"):
						r.URL.Path = filepath.Join(filepath.Dir(r.URL.Path), tt.repomdFileName)
					case strings.HasSuffix(r.URL.Path, "updateinfo.xml.gz"):
						r.URL.Path = filepath.Join(filepath.Dir(r.URL.Path), tt.updateInfoFileName)
					}
					http.StripPrefix("/pub/rocky/8/BaseOS/x86_64/os/repodata/", http.FileServer(http.Dir("testdata/fixtures")))
				} else {
					http.NotFound(w, r)
				}
			}))
			defer tsUpdateInfoURL.Close()

			dir := t.TempDir()
			rc := rocky.NewConfig(rocky.WithURL(tsUpdateInfoURL.URL+"/pub/rocky/%s/%s/%s/os/"), rocky.WithDir(dir), rocky.WithRetry(0), rocky.WithReleases([]string{"8"}), rocky.WithRepos([]string{"BaseOS"}), rocky.WithArches([]string{"x86_64"}))
			if err := rc.Update(); tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				return
			}

			err := filepath.Walk(dir, func(path string, info os.FileInfo, errfp error) error {
				if errfp != nil {
					return errfp
				}
				if info.IsDir() {
					return nil
				}

				dir, file := filepath.Split(path)
				want, err := os.ReadFile(filepath.Join("testdata", "golden", filepath.Base(dir), file))
				assert.NoError(t, err, "failed to open the golden file")

				got, err := os.ReadFile(path)
				assert.NoError(t, err, "failed to open the result file")

				assert.JSONEq(t, string(want), string(got))

				return nil
			})
			assert.Nil(t, err, "filepath walk error")
		})
	}
}
