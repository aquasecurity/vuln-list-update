package pypa

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/aquasecurity/vuln-list-update/types"
	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/cheggaaa/pb"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v2"
)

const (
	pypaDir            = "pypa"
	securityTrackerURL = "https://github.com/pypa/advisory-db/archive/refs/heads/main.zip"
	retry              = 3
	yamlExt            = ".yaml"
)

type options struct {
	url string
	dir string
}
type option func(*options)

type PyPA struct {
	opts  *options
	AppFs afero.Fs
}

func WithURL(url string) option {
	return func(opts *options) { opts.url = url }
}

func WithDir(dir string) option {
	return func(opts *options) { opts.dir = dir }
}

func NewPypa(opts ...option) PyPA {
	o := &options{
		url: securityTrackerURL,
		dir: filepath.Join(utils.VulnListDir(), pypaDir),
	}

	for _, opt := range opts {
		opt(o)
	}

	return PyPA{
		opts: o,
	}

}

func (pypa *PyPA) Update() error {
	dir, err := utils.DownloadToTempDir(context.Background(), pypa.opts.url)

	if err != nil {
		return xerrors.Errorf("failed to download %s: %w", pypa.opts.url, err)
	}

	vulnDir := filepath.Join(dir, "advisory-db-main", "vulns")

	yamlFiles, err := getYamlFiles(vulnDir)

	if err != nil {
		return xerrors.Errorf("failed to find vulnerability files in the directory %s: %w", vulnDir, err)
	}

	bar := pb.StartNew(len(yamlFiles))

	for _, file := range yamlFiles {
		data, err := os.ReadFile(file)

		if err != nil {
			return xerrors.Errorf("unable to read %s: %w", file, err)
		}

		osv := &types.Osv{}

		err = yaml.Unmarshal(data, osv)

		if err != nil {
			return xerrors.Errorf("unable to parse yaml %s: %w", file, err)
		}

		if err := utils.WriteJSON(afero.NewOsFs(), pypa.opts.dir, fmt.Sprintf("%s.json", osv.Id), osv); err != nil {
			return xerrors.Errorf("failed to write file: %w", err)
		}

		bar.Increment()
	}
	bar.Finish()
	return nil
}
func getYamlFiles(vulnDir string) ([]string, error) {
	yamlFiles := make([]string, 0)

	err := filepath.WalkDir(vulnDir,
		func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if !d.IsDir() && filepath.Ext(path) == yamlExt {
				yamlFiles = append(yamlFiles, path)
			}

			return nil
		})
	return yamlFiles, err

}
