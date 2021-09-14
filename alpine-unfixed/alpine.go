package alpineunfixed

import (
	"context"
	"encoding/json"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	alpineDir = "alpine-unfixed"
	secFixUrl = "https://aquasecurity.github.io/secfixes-tracker/all.tar.gz"
)

type Updater struct {
	*options
}

type options struct {
	vulnListDir string
	url         string
}

type option func(*options)

func WithVulnListDir(dir string) option {
	return func(opts *options) {
		opts.vulnListDir = dir
	}
}
func WithURL(url string) option {
	return func(opts *options) {
		opts.url = url
	}
}

func NewUpdater(opts ...option) Updater {
	o := &options{
		vulnListDir: utils.VulnListDir(),
		url:         secFixUrl,
	}

	for _, opt := range opts {
		opt(o)
	}
	return Updater{
		options: o,
	}
}

func (u Updater) Update() error {
	dir := filepath.Join(u.vulnListDir, alpineDir)
	log.Printf("Remove Alpine directory %s", dir)
	if err := os.RemoveAll(dir); err != nil {
		return xerrors.Errorf("failed to remove Alpine unfixed directory: %w", err)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return xerrors.Errorf("mkdir error: %w", err)
	}

	log.Println("Fetching Alpine unfixed data...")
	ctx := context.Background()
	tmpDir, err := utils.DownloadToTempDir(ctx, u.url)
	if err != nil {
		return xerrors.Errorf("alpine secfixes download error: %w", err)
	}
	defer os.RemoveAll(tmpDir) // nolint: errcheck

	log.Println("Saving Alpine unfixed data...")
	err = filepath.Walk(tmpDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		} else if info.IsDir() {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return xerrors.Errorf("file open error: %w", err)
		}

		var vuln unfixedVulnerability
		if err = json.NewDecoder(f).Decode(&vuln); err != nil {
			return xerrors.Errorf("JSON decode error: %w", err)
		}

		filePath := filepath.Join(dir, vuln.ID) + ".json"
		if err = utils.Write(filePath, vuln); err != nil {
			return xerrors.Errorf("write error: %w", err)
		}

		return nil
	})
	if err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}

	return nil
}
