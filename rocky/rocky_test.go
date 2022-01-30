package rocky_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/aquasecurity/vuln-list-update/rocky"
	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"
)

func Test_Update(t *testing.T) {
	tests := []struct {
		name          string
		rootDir       string
		releases      map[string]map[string][]string
		repository    []string
		expectedError error
	}{
		{
			name:          "happy path",
			rootDir:       "testdata/fixtures/happy",
			releases:      map[string]map[string][]string{"8": {"vault": {"8.4"}, "pub": {"8.5"}}},
			repository:    []string{"BaseOS", "AppStream"},
			expectedError: nil,
		},
		{
			name:          "not module in modules.yaml",
			rootDir:       "testdata/fixtures/not_module_in_yaml",
			releases:      map[string]map[string][]string{"8": {"pub": {"8.5"}}},
			repository:    []string{"AppStream"},
			expectedError: nil,
		},
		{
			name:          "bad updateInfo response",
			rootDir:       "testdata/fixtures/updateinfo_invalid",
			releases:      map[string]map[string][]string{"8": {"pub": {"8.5"}}},
			repository:    []string{"BaseOS"},
			expectedError: xerrors.Errorf("failed to update security advisories of Rocky Linux 8 BaseOS x86_64: %w", errors.New("failed to fetch updateInfo")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/", http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				fmt.Println()
				if _, file := filepath.Split(filepath.Clean(r.URL.Path)); file == "repodata" {
					r.URL.Path = filepath.Join(r.URL.Path, "repodata")
				}
				http.FileServer(http.Dir(tt.rootDir)).ServeHTTP(rw, r)

			}))
			tsUpdateInfoURL := httptest.NewServer(mux)
			defer tsUpdateInfoURL.Close()

			dir := t.TempDir()
			rc := rocky.NewConfig(rocky.With(tsUpdateInfoURL.URL+"/%s/rocky/%s/%s/%s/os/repodata", dir, 0, tt.releases, tt.repository, []string{"x86_64"}))
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
				b, err := os.ReadFile(filepath.Join("testdata", "golden", filepath.Base(dir), file))
				assert.NoError(t, err, "failed to open the result file")
				var want rocky.Advisory
				err = json.Unmarshal(b, &want)
				assert.NoError(t, err, "failed to unmarshal json")
				sort.Slice(want.Packages, func(i, j int) bool { return want.Packages[i].String() < want.Packages[j].String() })
				sort.Slice(want.PkgLists, func(i, j int) bool { return want.PkgLists[i].Module.String() < want.PkgLists[j].Module.String() })
				for i, pkglist := range want.PkgLists {
					sort.Slice(pkglist.Packages, func(i, j int) bool { return pkglist.Packages[i].String() < pkglist.Packages[j].String() })
					want.PkgLists[i] = pkglist
				}

				b, err = os.ReadFile(path)
				assert.NoError(t, err, "failed to open the result file")
				var got rocky.Advisory
				err = json.Unmarshal(b, &got)
				assert.NoError(t, err, "failed to unmarshal json")
				sort.Slice(got.Packages, func(i, j int) bool { return got.Packages[i].String() < got.Packages[j].String() })
				sort.Slice(got.PkgLists, func(i, j int) bool { return got.PkgLists[i].Module.String() < got.PkgLists[j].Module.String() })
				for i, pkglist := range got.PkgLists {
					sort.Slice(pkglist.Packages, func(i, j int) bool { return pkglist.Packages[i].String() < pkglist.Packages[j].String() })
					got.PkgLists[i] = pkglist
				}

				if !reflect.DeepEqual(got, want) {
					t.Errorf("[%s]\n diff: %s", tt.name, pretty.Compare(got, want))
				}

				return nil
			})
			assert.Nil(t, err, "filepath walk error")
		})
	}
}
