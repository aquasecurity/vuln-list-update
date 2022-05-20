package rocky_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/vuln-list-update/rocky"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"
)

func Test_Update(t *testing.T) {
	tests := []struct {
		name             string
		releasesFilePath string
		rootDir          string
		repository       []string
		expectedError    error
	}{
		{
			name:             "happy path",
			releasesFilePath: "testdata/fixtures/releases/happy.html",
			rootDir:          "testdata/fixtures/happy",
			repository:       []string{"BaseOS"},
			expectedError:    nil,
		},
		{
			name:             "bad repomd response",
			releasesFilePath: "testdata/fixtures/releases/happy.html",
			rootDir:          "testdata/fixtures/repomd_invalid",
			repository:       []string{"BaseOS"},
			expectedError:    xerrors.Errorf("failed to update security advisories of Rocky Linux 8.5 BaseOS x86_64: %w", errors.New("failed to fetch updateInfo path from repomd.xml")),
		},
		{
			name:             "bad updateInfo response",
			releasesFilePath: "testdata/fixtures/releases/happy.html",
			rootDir:          "testdata/fixtures/updateinfo_invalid",
			repository:       []string{"BaseOS"},
			expectedError:    xerrors.Errorf("failed to update security advisories of Rocky Linux 8.5 BaseOS x86_64: %w", errors.New("failed to fetch updateInfo")),
		},
		{
			name:             "no updateInfo field(BaseOS)",
			releasesFilePath: "testdata/fixtures/releases/happy.html",
			rootDir:          "testdata/fixtures/no_updateinfo_field",
			repository:       []string{"BaseOS"},
			expectedError:    xerrors.Errorf("failed to update security advisories of Rocky Linux 8.5 BaseOS x86_64: %w", xerrors.Errorf("failed to fetch updateInfo path from repomd.xml: %w", rocky.ErrorNoUpdateInfoField)),
		},
		{
			name:             "no updateInfo field(extras)",
			releasesFilePath: "testdata/fixtures/releases/happy.html",
			rootDir:          "testdata/fixtures/no_updateinfo_field",
			repository:       []string{"extras"},
			expectedError:    nil,
		},
		{
			name:             "empty list of releases",
			releasesFilePath: "testdata/fixtures/releases/empty.html",
			repository:       []string{"BaseOS"},
			expectedError:    xerrors.Errorf("failed to update security advisories of Rocky Linux: %w", errors.New("failed to get list of releases: list is empty")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.Handle("/pub/rocky/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, tt.releasesFilePath)
			}))
			mux.Handle("/pub/rocky/8.5/extras/x86_64/os/repodata/", http.StripPrefix("/pub/rocky/8.5/extras/x86_64/os/repodata/", http.FileServer(http.Dir(tt.rootDir))))
			mux.Handle("/pub/rocky/8.5/BaseOS/x86_64/os/repodata/", http.StripPrefix("/pub/rocky/8.5/BaseOS/x86_64/os/repodata/", http.FileServer(http.Dir(tt.rootDir))))
			tsUpdateInfoURL := httptest.NewServer(mux)
			defer tsUpdateInfoURL.Close()

			dir := t.TempDir()
			rc := rocky.NewConfig(rocky.With(tsUpdateInfoURL.URL+"/pub/rocky", "%s/%s/%s/%s/os/", dir, 0, tt.repository, []string{"x86_64"}))
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
