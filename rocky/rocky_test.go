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
			expectedError: xerrors.Errorf("failed to update security advisories of Rocky Linux 8 BaseOS x86_64: %w", errors.New("failed to fetch updateInfo path from repomd.xml")),
		},
		{
			name:          "bad updateInfo response",
			rootDir:       "testdata/fixtures/updateinfo_invalid",
			repository:    []string{"BaseOS"},
			expectedError: xerrors.Errorf("failed to update security advisories of Rocky Linux 8 BaseOS x86_64: %w", errors.New("failed to fetch updateInfo")),
		},
		{
			name:          "no updateInfo field(BaseOS)",
			rootDir:       "testdata/fixtures/no_updateinfo_field",
			repository:    []string{"BaseOS"},
			expectedError: xerrors.Errorf("failed to update security advisories of Rocky Linux 8 BaseOS x86_64: %w", xerrors.Errorf("failed to fetch updateInfo path from repomd.xml: %w", rocky.ErrorNoUpdateInfoField)),
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
			tsUpdateInfoURL := httptest.NewServer(http.StripPrefix("/pub/rocky/8/", http.FileServer(http.Dir(tt.rootDir))))
			defer tsUpdateInfoURL.Close()

			dir := t.TempDir()
			rc := rocky.NewConfig(rocky.With(map[string]string{"rocky": tsUpdateInfoURL.URL + "/pub/rocky/%s/%s/%s/os/", "koji": tsUpdateInfoURL.URL + "/kojifiles/packages/"}, dir, 1, 1, 0, []string{"8"}, tt.repository, []string{"x86_64"}))
			err := rc.Update()
			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				return
			}
			assert.NoError(t, err)

			err = filepath.Walk(dir, func(path string, info os.FileInfo, errfp error) error {
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
