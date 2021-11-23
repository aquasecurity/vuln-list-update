package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/cheggaaa/pb"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"
)

const (
	securityTrackerURL = "https://osv-vulnerabilities.storage.googleapis.com/%s/all.zip"
	osvDir             = "osv"
)

var defaultEcosystemDirs = map[string]string{
	"PyPI":      "python",
	"Go":        "go",
	"crates.io": "rust",
}

type options struct {
	url           string
	dir           string
	ecosystemDirs map[string]string
}

type option func(*options)

type Osv struct {
	opts *options
}

func WithURL(url string) option {
	return func(opts *options) {
		opts.url = url
	}
}

func WithDir(dir string) option {
	return func(opts *options) {
		opts.dir = dir
	}
}

func WithEcosystem(ecosystemDir map[string]string) option {
	return func(opts *options) {
		opts.ecosystemDirs = ecosystemDir
	}
}

func NewOsv(opts ...option) Osv {
	o := &options{}

	for _, opt := range opts {
		opt(o)
	}

	if len(o.ecosystemDirs) == 0 {
		ecosystemDirs := make(map[string]string)
		for name, dir := range defaultEcosystemDirs {
			ecosystemDirs[name] = dir
		}
		o.ecosystemDirs = ecosystemDirs
	}

	if o.url == "" {
		o.url = securityTrackerURL
	}

	if o.dir == "" {
		o.dir = filepath.Join(utils.VulnListDir(), osvDir)
	}

	return Osv{
		opts: o,
	}
}

func (osv *Osv) Update() error {
	allfiles, err := osv.getAllFiles()
	if err != nil {
		return xerrors.Errorf("failed to get files: %w", err)
	}

	bar := pb.StartNew(osv.getAmountFiles(allfiles))

	for ecosystemDir, files := range allfiles {
		for _, file := range files {
			data, err := os.ReadFile(file)

			if err != nil {
				return xerrors.Errorf("unable to read %s: %w", file, err)
			}

			osvJson := &OsvJson{}

			err = json.Unmarshal(data, osvJson)

			if err != nil {
				return xerrors.Errorf("unable to parse json %s: %w", file, err)
			}

			if err := utils.WriteJSON(afero.NewOsFs(), filepath.Join(osv.opts.dir, ecosystemDir, osvJson.Affected[0].Package.Name), fmt.Sprintf("%s.json", osvJson.Id), osvJson); err != nil {
				return xerrors.Errorf("failed to write file: %w", err)
			}

			bar.Increment()
		}
	}
	bar.Finish()
	return nil
}

func (osv *Osv) getAmountFiles(allFiles map[string][]string) int {
	amount := 0
	for ecosystem := range allFiles {
		amount += len(allFiles[ecosystem])
	}
	return amount
}

func (osv *Osv) getAllFiles() (map[string][]string, error) {
	allfiles := make(map[string][]string)

	if len(osv.opts.ecosystemDirs) == 0 {
		return nil, xerrors.Errorf("no files to download, ecosystems: %s", osv.opts.ecosystemDirs)
	}
	for ecoSystem, ecoSystemDir := range osv.opts.ecosystemDirs {
		tempDir, err := utils.DownloadToTempDir(context.Background(), fmt.Sprintf(osv.opts.url, ecoSystem))
		if err != nil {
			return nil, xerrors.Errorf("failed to download %s: %w", fmt.Sprintf(osv.opts.url, ecoSystem), err)
		}

		ecoSystemFiles, err := getEcosystemFiles(tempDir)
		if err != nil {
			return nil, xerrors.Errorf("failed to find vulnerability files in the directory %s: %w", tempDir, err)
		}
		allfiles[ecoSystemDir] = ecoSystemFiles
	}
	return allfiles, nil
}
func getEcosystemFiles(dir string) ([]string, error) {
	files := make([]string, 0)

	err := filepath.WalkDir(dir,
		func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if !d.IsDir() {
				files = append(files, path)
			}

			return nil
		})
	return files, err
}
