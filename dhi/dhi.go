// Package dhi mirrors Docker Hardened Images OSV advisories into vuln-list.
package dhi

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/osv"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const defaultURL = "https://github.com/docker-hardened-images/advisories/archive/refs/heads/main.tar.gz"

// Updater fetches the canonical DHI advisory repository.
type Updater struct {
	url string
}

// NewUpdater returns an updater for Docker's public advisory repository.
func NewUpdater() Updater { return Updater{url: defaultURL} }

// Update downloads and publishes only JSON files below osv/dhi.
func (u Updater) Update() error {
	source, err := utils.DownloadToTempDir(context.Background(), u.url)
	if err != nil {
		return xerrors.Errorf("failed to download DHI advisories: %w", err)
	}
	return updateFromDir(source, filepath.Join(utils.VulnListDir(), "dhi"))
}

func updateFromDir(source, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		return xerrors.Errorf("failed to create vuln-list directory: %w", err)
	}
	staging, err := os.MkdirTemp(filepath.Dir(target), ".dhi-")
	if err != nil {
		return xerrors.Errorf("failed to create staging directory: %w", err)
	}
	defer os.RemoveAll(staging)

	var count int
	err = filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".json" || !inDHIPath(path) {
			return nil
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var record osv.OSV
		if err = json.Unmarshal(raw, &record); err != nil {
			return xerrors.Errorf("invalid DHI OSV record %s: %w", path, err)
		}
		if record.ID == "" || len(record.Affected) == 0 {
			return xerrors.Errorf("invalid DHI OSV record %s: id and affected are required", path)
		}
		if err = os.WriteFile(filepath.Join(staging, filepath.Base(path)), raw, 0600); err != nil {
			return err
		}
		count++
		return nil
	})
	if err != nil {
		return xerrors.Errorf("failed to stage DHI advisories: %w", err)
	}
	if count == 0 {
		return xerrors.New("no DHI OSV advisories found under osv/dhi")
	}

	if err = os.RemoveAll(target); err != nil {
		return xerrors.Errorf("failed to remove previous DHI advisories: %w", err)
	}
	if err = os.Rename(staging, target); err != nil {
		return xerrors.Errorf("failed to publish DHI advisories: %w", err)
	}
	return nil
}

func inDHIPath(path string) bool {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "osv" && parts[i+1] == "dhi" {
			return true
		}
	}
	return false
}
