package fedora_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aquasecurity/vuln-list-update/fedora"
	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Update(t *testing.T) {
	type args struct {
		mode         string
		uinfoURLPath string
		release      []string
		repos        []string
		arches       []string
	}
	tests := []struct {
		name          string
		rootDir       string
		args          args
		expectedError error
	}{
		{
			name:    "fedora 35",
			rootDir: "testdata/fixtures/fedora35",
			args: args{
				mode:         "fedora",
				uinfoURLPath: "/pub/fedora/linux/updates/%s/%s/%s/",
				release:      []string{"35"},
				repos:        []string{"Everything", "Modular"},
				arches:       []string{"x86_64"},
			},
			expectedError: nil,
		},
		{
			name:    "epel 7",
			rootDir: "testdata/fixtures/epel7",
			args: args{
				mode:         "epel",
				uinfoURLPath: "/pub/epel/%s/%s/",
				release:      []string{"7"},
				repos:        []string{},
				arches:       []string{"x86_64"},
			},
			expectedError: nil,
		},
		{
			name:    "epel 8",
			rootDir: "testdata/fixtures/epel8",
			args: args{
				mode:         "epel",
				uinfoURLPath: "/pub/epel/%s/%s/%s/",
				release:      []string{"8"},
				repos:        []string{"Everything"},
				arches:       []string{"x86_64"},
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.Handle("/pub/", http.FileServer(http.Dir(tt.rootDir)))
			mux.Handle("/packages/", http.FileServer(http.Dir(tt.rootDir)))
			mux.HandleFunc("/show_bug.cgi", func(rw http.ResponseWriter, r *http.Request) {
				bugzillaID := r.URL.Query().Get("id")
				r.URL.Path = fmt.Sprintf("%s.xml", bugzillaID)
				r.URL.RawQuery = ""
				http.FileServer(http.Dir(filepath.Join(tt.rootDir, "bugzilla"))).ServeHTTP(rw, r)
			})
			tsServerURL := httptest.NewServer(mux)
			defer tsServerURL.Close()

			dir := t.TempDir()
			fd := fedora.NewConfig(fedora.With(map[string]string{tt.args.mode: tsServerURL.URL + tt.args.uinfoURLPath, "bugzilla": tsServerURL.URL + "/show_bug.cgi?ctype=xml&id=%s", "moduleinfo": tsServerURL.URL + "/packages/%s/%s/%d.%s/files/module/modulemd.%s.txt"}, dir, 1, 0, 0, map[string][]string{tt.args.mode: tt.args.release}, tt.args.repos, tt.args.arches))
			if err := fd.Update(); tt.expectedError != nil {
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
				b, err := os.ReadFile(filepath.Join("testdata", "golden", filepath.Base(dir), file))
				assert.NoError(t, err, "failed to open the golden file")
				var want fedora.FSA
				err = json.Unmarshal(b, &want)
				assert.NoError(t, err, "failed to unmarshal json")

				b, err = os.ReadFile(path)
				assert.NoError(t, err, "failed to open the result file")
				var got fedora.FSA
				err = json.Unmarshal(b, &got)
				assert.NoError(t, err, "failed to unmarshal json")

				if !reflect.DeepEqual(got, want) {
					t.Errorf("[%s]\n diff: %s", tt.name, pretty.Compare(got, want))
				}

				return nil
			})
			assert.Nil(t, err, "filepath walk error")
		})
	}
}
