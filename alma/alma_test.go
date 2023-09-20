package alma_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/alma"
)

func TestUpdate(t *testing.T) {
	tests := []struct {
		name          string
		version       string
		inputJSONFile string
		expectedError error
	}{
		{
			name:          "happy path",
			version:       "8",
			inputJSONFile: "testdata/errata.json",
			expectedError: nil,
		},
		{
			name:          "sad path, invalid release version",
			version:       "9",
			inputJSONFile: "",
			expectedError: xerrors.Errorf("failed to update security advisories of AlmaLinux 9: %w", errors.New("failed to fetch security advisories from AlmaLinux")),
		},
		{
			name:          "sad path, invalid json",
			version:       "8",
			inputJSONFile: "testdata/invalid.json",
			expectedError: xerrors.Errorf("failed to update security advisories of AlmaLinux 8: %w", errors.New("failed to unmarshal json")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.inputJSONFile == "" {
					http.NotFound(w, r)
					return
				}
				http.ServeFile(w, r, tt.inputJSONFile)
			}))
			defer ts.Close()

			dir := t.TempDir()
			ac := alma.NewConfig(alma.WithURLs(map[string]string{tt.version: ts.URL}), alma.WithDir(dir), alma.WithRetry(0))

			if err := ac.Update(); tt.expectedError != nil {
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
