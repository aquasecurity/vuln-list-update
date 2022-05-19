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
		name          string
		rootDir       string
		repository    []string
		expectedError error
	}{
		{
			name:          "happy path",
			rootDir:       "testdata/fixtures/happy",
			repository:    []string{"BaseOS"},
			expectedError: nil,
		},
		{
			name:          "bad repomd response",
			rootDir:       "testdata/fixtures/repomd_invalid",
			repository:    []string{"BaseOS"},
			expectedError: xerrors.Errorf("failed to update security advisories of Rocky Linux 8.5 BaseOS x86_64: %w", errors.New("failed to fetch updateInfo path from repomd.xml")),
		},
		{
			name:          "bad updateInfo response",
			rootDir:       "testdata/fixtures/updateinfo_invalid",
			repository:    []string{"BaseOS"},
			expectedError: xerrors.Errorf("failed to update security advisories of Rocky Linux 8.5 BaseOS x86_64: %w", errors.New("failed to fetch updateInfo")),
		},
		{
			name:          "no updateInfo field(BaseOS)",
			rootDir:       "testdata/fixtures/no_updateinfo_field",
			repository:    []string{"BaseOS"},
			expectedError: xerrors.Errorf("failed to update security advisories of Rocky Linux 8.5 BaseOS x86_64: %w", xerrors.Errorf("failed to fetch updateInfo path from repomd.xml: %w", rocky.ErrorNoUpdateInfoField)),
		},
		{
			name:          "no updateInfo field(extras)",
			rootDir:       "testdata/fixtures/no_updateinfo_field",
			repository:    []string{"extras"},
			expectedError: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			savedGetReleasesList := rocky.GetReleasesList
			rocky.GetReleasesList = func(url string) ([]string, error) { return []string{"8.5"}, nil }
			tsUpdateInfoURL := httptest.NewServer(http.StripPrefix("/pub/rocky/8.5/BaseOS/x86_64/os/repodata/", http.FileServer(http.Dir(tt.rootDir))))
			defer func() {
				tsUpdateInfoURL.Close()
				rocky.GetReleasesList = savedGetReleasesList
			}()

			dir := t.TempDir()
			rc := rocky.NewConfig(rocky.With(tsUpdateInfoURL.URL+"/pub/rocky/%s/%s/%s/os/", dir, 0, tt.repository, []string{"x86_64"}))
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

func Test_GetReleasesList(t *testing.T) {
	tests := []struct {
		name         string
		filepath     string
		wantReleases []string
		wantErr      string
	}{
		{
			name:         "happy path",
			filepath:     "testdata/fixtures/releases/happy.html",
			wantReleases: []string{"8.5", "8.6"},
		},
		{
			name:     "empty releases",
			filepath: "testdata/fixtures/releases/empty.html",
			wantErr:  "failed to get list of releases: list is empty",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, test.filepath)
			}))
			defer ts.Close()

			releases, err := rocky.GetReleasesList(ts.URL)

			if test.wantErr != "" {
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), test.wantErr)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, test.wantReleases, releases)
			}

		})
	}
}
