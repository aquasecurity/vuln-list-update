package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/aquasecurity/vuln-list-update/utils"
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

type OSV struct {
	*options
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

func NewOsv(opts ...option) OSV {
	o := &options{
		url:           securityTrackerURL,
		dir:           filepath.Join(utils.VulnListDir(), osvDir),
		ecosystemDirs: defaultEcosystemDirs,
	}
	for _, option := range opts {
		option(o)
	}
	return OSV{
		options: o,
	}
}

func (osv *OSV) Update() error {
	for ecoSystem, ecoSystemDir := range osv.ecosystemDirs {
		log.Printf("Updating OSV %s advisories", ecoSystem)
		tempDir, err := utils.DownloadToTempDir(context.Background(), fmt.Sprintf(osv.url, ecoSystem))
		if err != nil {
			return xerrors.Errorf("failed to download %s: %w", fmt.Sprintf(osv.url, ecoSystem), err)
		}

		err = filepath.WalkDir(tempDir, func(path string, d fs.DirEntry, err error) error {
			if !d.IsDir() {
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				osvJson := &OsvJson{}
				err = json.Unmarshal(data, osvJson)
				if err != nil {
					return xerrors.Errorf("unable to parse json %s: %w", path, err)
				}

				if err := utils.WriteJSON(afero.NewOsFs(), filepath.Join(osv.dir, ecoSystemDir, osvJson.Affected[0].Package.Name), fmt.Sprintf("%s.json", osvJson.Id), osvJson); err != nil {
					return xerrors.Errorf("failed to write file: %w", err)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}
