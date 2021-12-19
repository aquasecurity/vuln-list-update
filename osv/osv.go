package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
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

type Database struct {
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

func NewOsv(opts ...option) Database {
	o := &options{
		url:           securityTrackerURL,
		dir:           filepath.Join(utils.VulnListDir(), osvDir),
		ecosystemDirs: defaultEcosystemDirs,
	}
	for _, opt := range opts {
		opt(o)
	}
	return Database{
		options: o,
	}
}

func (osv *Database) Update() error {
	ctx := context.Background()
	for ecoSystem, ecoSystemDir := range osv.ecosystemDirs {
		log.Printf("Updating OSV %s advisories", ecoSystem)
		tempDir, err := utils.DownloadToTempDir(ctx, fmt.Sprintf(osv.url, ecoSystem))
		if err != nil {
			return xerrors.Errorf("failed to download %s: %w", fmt.Sprintf(osv.url, ecoSystem), err)
		}

		err = filepath.WalkDir(tempDir, func(path string, d fs.DirEntry, err error) error {
			if !d.IsDir() {
				f, err := os.Open(path)
				if err != nil {
					return xerrors.Errorf("file open error (%s): %w", path, err)
				}

				var parsed OSV
				if err = json.NewDecoder(f).Decode(&parsed); err != nil {
					return xerrors.Errorf("unable to parse json %s: %w", path, err)
				}

				filePath := filepath.Join(osv.dir, ecoSystemDir, parsed.Affected[0].Package.Name, fmt.Sprintf("%s.json", parsed.ID))
				if err = utils.Write(filePath, parsed); err != nil {
					return xerrors.Errorf("failed to write file: %w", err)
				}
			}
			return nil
		})
		if err != nil {
			return xerrors.Errorf("walk error: %w", err)
		}
	}
	return nil
}
