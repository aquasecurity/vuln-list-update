package tracker_test

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/debian/tracker"

	"github.com/stretchr/testify/assert"
)

func TestClient_Update(t *testing.T) {
	testCases := []struct {
		name          string
		version       string
		existedFiles  []string
		jsonFileName  string
		path          string
		expectedError string
	}{
		{
			name:          "happy path",
			jsonFileName:  "testdata/fixtures/debian.json",
			path:          "debian.json",
			expectedError: "",
		},
		{
			name:          "remove old files",
			existedFiles:  []string{"CVE-0000-0000", "CVE-3000-0000"},
			jsonFileName:  "testdata/fixtures/debian.json",
			path:          "debian.json",
			expectedError: "",
		},
		{
			name:          "invalid JSON",
			jsonFileName:  "testdata/fixtures/invalid.json",
			path:          "invalid.json",
			expectedError: "invalid character 'i' looking for beginning of value",
		},
		{
			name:          "404",
			jsonFileName:  "testdata/fixtures/debian.json",
			path:          "404.html",
			expectedError: "HTTP error. status code: 404",
		},
	}

	for _, tc := range testCases {
		//t.Run(tc.name, func(t *testing.T) {
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, ".json"):
				j, _ := ioutil.ReadFile(tc.jsonFileName)
				_, _ = w.Write(j)
			case strings.HasSuffix(r.URL.Path, "404.html"):
				http.NotFound(w, r)
			default:
				assert.Fail(t, "bad URL requested: ", r.URL.Path, tc.name)
			}
		}))
		defer testServer.Close()

		fmt.Println(path.Join(testServer.URL, tc.path))
		dir, err := ioutil.TempDir("", "debian")
		assert.NoError(t, err, "failed to create temp dir")
		defer os.RemoveAll(dir)

		// These files must be removed
		if len(tc.existedFiles) > 0 {
			d := filepath.Join(dir, "debian")
			_ = os.Mkdir(d, 0777)
			for _, fileName := range tc.existedFiles {
				err = ioutil.WriteFile(filepath.Join(d, fileName), []byte("test"), 0666)
				assert.Nil(t, err, "failed to write the file")
			}
		}

		u, err := url.Parse(testServer.URL)
		assert.NoError(t, err, "URL parse error")
		u.Path = path.Join(u.Path, tc.path)

		client := tracker.Client{
			URL:         u.String(),
			VulnListDir: dir,
			Retry:       0,
		}
		err = client.Update()
		switch {
		case tc.expectedError != "":
			assert.Contains(t, err.Error(), tc.expectedError, tc.name)
		default:
			assert.NoError(t, err, tc.name)
		}

		// TODO: Expose utils with an interface so this can self contain Write()
		// Compare got and golden
		err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return xerrors.Errorf("walk error: %w", err)
			}
			if info.IsDir() {
				return nil
			}

			// Before: /var/folders/j7/pvz71jxn637dqd96gm80nhwm0000gn/T/debian676766850/debian/prototypejs/CVE-2007-2383.json
			// After:  testdata/goldens/debian/prototypejs/CVE-2007-2383.json.golden
			paths := strings.Split(path, string(os.PathSeparator))
			p := filepath.Join(paths[len(paths)-3:]...)
			golden := filepath.Join("testdata", "goldens", p+".golden")

			want, err := ioutil.ReadFile(golden)
			assert.NoError(t, err, "failed to open the golden file")

			got, err := ioutil.ReadFile(path)
			assert.NoError(t, err, "failed to open the result file")

			assert.Equal(t, string(want), string(got))

			return nil
		})
		assert.NoError(t, err, "filepath walk error")
		//})
	}
}
