package glad

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "update golden files")

func TestUpdater_WalkDir(t *testing.T) {
	testCases := []struct {
		name          string
		appFs         afero.Fs
		rootDir       string
		goldenDir     string
		wantFileCount int
		wantErr       string
	}{
		{
			name:          "happy path",
			rootDir:       "testdata/happy",
			goldenDir:     "testdata/golden/happy",
			wantFileCount: 6,
		},
		{
			name:          "happy path, skip slug update for maven",
			rootDir:       "testdata/skip-slug-update",
			goldenDir:     "testdata/golden/skip-slug-update",
			wantFileCount: 2,
		},
		{
			name:    "sad path",
			rootDir: "testdata/sad",
			wantErr: "yaml: unmarshal errors",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			base := afero.NewOsFs()
			roBase := afero.NewReadOnlyFs(base)
			ufs := afero.NewCopyOnWriteFs(roBase, afero.NewMemMapFs())

			c := Updater{
				vulnListDir: "./tmp",
				cacheDir:    "./cache",
				appFs:       ufs,
			}

			err := c.walkDir(tc.rootDir)
			if tc.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tc.wantErr, tc.name)
				return
			}
			assert.NoError(t, err)

			fileCount := 0
			err = afero.Walk(c.appFs, "./tmp", func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				fileCount += 1

				got, err := afero.ReadFile(c.appFs, path)
				assert.NoError(t, err, path)

				relPath, err := filepath.Rel(c.vulnListDir, path)
				require.NoError(t, err, path)

				goldenPath := filepath.Join(tc.goldenDir, relPath)
				if *update {
					err = os.WriteFile(goldenPath, got, 0666)
					assert.NoError(t, err, tc.name)
				}

				want, err := os.ReadFile(goldenPath)
				assert.NoError(t, err, goldenPath)

				assert.JSONEq(t, string(want), string(got), tc.name)

				return nil
			})
			assert.Equal(t, tc.wantFileCount, fileCount)
			assert.NoError(t, err, tc.name)
		})
	}
}

func Test_searchPrefix(t *testing.T) {
	tests := []struct {
		name         string
		adv          advisory
		advisories   []advisory
		expectedSlug string
	}{
		{
			name: "update slug",
			adv:  advisory{PackageSlug: "go/github.com/apache/thrift/lib/go/thrift"},
			advisories: []advisory{
				{PackageSlug: "go/github.com/apache/thrift/lib/go/thrift"},
				{PackageSlug: "go/github.com/apache/thrift-mini"},
				{PackageSlug: "go/github.com/apache/thrift"},
			},
			expectedSlug: "go/github.com/apache/thrift",
		},
		{
			name:         "same slugs",
			adv:          advisory{PackageSlug: "github.com/kubernetes/kubernetes"},
			advisories:   []advisory{{PackageSlug: "github.com/kubernetes/kubernetes"}},
			expectedSlug: "",
		},
		{
			name: "slug with same prefix in bottom folder",
			adv:  advisory{PackageSlug: "go/github.com/apache/thrift-mini"},
			advisories: []advisory{
				{PackageSlug: "go/github.com/apache/thrift"},
			},
			expectedSlug: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			u := Updater{}
			slug := u.searchPrefix(test.adv.PackageSlug, test.advisories)

			assert.Equal(t, test.expectedSlug, slug)
		})
	}
}
