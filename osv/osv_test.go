package osv_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/vuln-list-update/osv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Update(t *testing.T) {
	type ecosystem struct {
		name string
		dir  string
	}
	type fstruct struct {
		eco  ecosystem
		pkg  string
		name string
	}

	var (
		defaultInputArchive = "testdata/%[1]s/all.zip"
		pythonEco           = ecosystem{"PyPI", "python"}
		pythonFiles         = []fstruct{{pythonEco, "trac", "PYSEC-2005-1.json"}, {pythonEco, "cherrypy", "PYSEC-2006-1.json"}, {pythonEco, "trac", "PYSEC-2006-2.json"}}
		goEco               = ecosystem{"Go", "go"}
		goFiles             = []fstruct{{goEco, "github.com/gin-gonic/gin", "GO-2020-0001.json"}, {goEco, "github.com/seccomp/libseccomp-golang", "GO-2020-0007.json"}, {goEco, "github.com/tidwall/gjson", "GO-2021-0059.json"}}
		rustEco             = ecosystem{"crates.io", "rust"}
		rustFiles           = []fstruct{{rustEco, "openssl", "RUSTSEC-2016-0001.json"}, {rustEco, "smallvec", "RUSTSEC-2019-0009.json"}, {rustEco, "tar", "RUSTSEC-2018-0002.json"}}
	)

	tests := []struct {
		name          string
		inputArchives string
		ecosystem     []ecosystem
		wantFiles     []fstruct
	}{
		{
			name:      "happy path python",
			ecosystem: []ecosystem{pythonEco},
			wantFiles: pythonFiles,
		},
		{
			name:      "happy path Go",
			ecosystem: []ecosystem{goEco},
			wantFiles: goFiles,
		},
		{
			name:      "happy path python+rust",
			ecosystem: []ecosystem{pythonEco, rustEco},
			wantFiles: append(pythonFiles, rustFiles...),
		},
		{
			name:      "sad path, unable to download archive",
			wantFiles: []fstruct{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			for _, ecosystem := range tt.ecosystem {
				b, err := os.ReadFile(fmt.Sprintf(defaultInputArchive, ecosystem.name))
				require.NoError(t, err)
				mux.HandleFunc(fmt.Sprintf("/%s/", ecosystem.name), func(w http.ResponseWriter, r *http.Request) {
					w.Write(b)
				})
			}
			ts := httptest.NewServer(mux)

			defer ts.Close()

			//build test settings
			testDir := t.TempDir()
			testUrl := ts.URL + "/%[1]s/" + defaultInputArchive
			testEcosystemDir := make(map[string]string)
			for _, ecosystem := range tt.ecosystem {
				testEcosystemDir[ecosystem.name] = ecosystem.dir
			}

			c := osv.NewOsv(osv.WithURL(testUrl), osv.WithDir(testDir), osv.WithEcosystem(testEcosystemDir))
			err := c.Update()
			require.NoError(t, err)

			for _, f := range tt.wantFiles {
				filePath := filepath.Join(f.eco.dir, f.pkg, f.name)
				gotJSON, err := os.ReadFile(filepath.Join(testDir, filePath))
				require.NoError(t, err)

				wantJSON, err := os.ReadFile(filepath.Join("testdata", f.eco.name, "golden", f.pkg, f.name))
				require.NoError(t, err)

				assert.JSONEq(t, string(wantJSON), string(gotJSON))
			}
		})
	}
}
