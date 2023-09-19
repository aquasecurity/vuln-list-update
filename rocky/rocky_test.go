package rocky_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/rocky"
)

func Test_Update(t *testing.T) {
	tests := []struct {
		name             string
		releasesFilePath string
		rootDir          string
		repository       []string
		wantErr          string
	}{
		{
			name:             "happy path",
			releasesFilePath: "testdata/fixtures/releases/happy.html",
			rootDir:          "testdata/fixtures/happy",
			repository:       []string{"BaseOS"},
		},
		{
			name:             "bad repomd response",
			releasesFilePath: "testdata/fixtures/releases/happy.html",
			rootDir:          "testdata/fixtures/repomd_invalid",
			repository:       []string{"BaseOS"},
			wantErr:          "failed to get security advisories from",
		},
		{
			name:             "bad updateInfo response",
			releasesFilePath: "testdata/fixtures/releases/happy.html",
			rootDir:          "testdata/fixtures/updateinfo_invalid",
			repository:       []string{"BaseOS"},
			wantErr:          "failed to fetch updateInfo",
		},
		{
			name:             "no updateInfo field(BaseOS)",
			releasesFilePath: "testdata/fixtures/releases/happy.html",
			rootDir:          "testdata/fixtures/no_updateinfo_field",
			repository:       []string{"BaseOS"},
			wantErr:          "failed to get security advisories from",
		},
		{
			name:             "no updateInfo field(extras)",
			releasesFilePath: "testdata/fixtures/releases/happy.html",
			rootDir:          "testdata/fixtures/no_updateinfo_field",
			repository:       []string{"extras"},
		},
		{
			name:             "no repomd file",
			releasesFilePath: "testdata/fixtures/releases/happy.html",
			rootDir:          "testdata/fixtures/releases",
			repository:       []string{"BaseOS"},
			wantErr:          "failed to get security advisories from",
		},
		{
			name:             "empty list of releases",
			releasesFilePath: "testdata/fixtures/releases/empty.html",
			repository:       []string{"BaseOS"},
			wantErr:          "list is empty",
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
			rc := rocky.NewConfig(rocky.With("%s/%s/%s/%s/os/", dir, 0, tt.repository, []string{"x86_64"}, []string{tsUpdateInfoURL.URL + "/pub/rocky"}))
			if err := rc.Update(); tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
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
