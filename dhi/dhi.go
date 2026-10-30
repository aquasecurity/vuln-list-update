// Package dhi mirrors Docker Hardened Images OSV advisories into vuln-list.
//
// The source is the dhi/osv tree on the main branch of
// https://github.com/docker-hardened-images/advisories. Records are published
// one file per advisory under year directories (dhi/osv/<YYYY>/<DHI-id>.json),
// with optional checksum and signature sidecars beside them and the matching
// OpenVEX documents in a separate dhi/vex tree, which is not mirrored.
package dhi

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/osv"
	"github.com/aquasecurity/vuln-list-update/utils"
)

// defaultURL extracts only the dhi/osv tree from the main branch archive.
const defaultURL = "https://github.com/docker-hardened-images/advisories/archive/refs/heads/main.tar.gz//advisories-main/dhi/osv"

// Updater fetches the canonical DHI advisory repository.
type Updater struct {
	url string
}

// NewUpdater returns an updater for Docker's public advisory repository.
func NewUpdater() Updater { return Updater{url: defaultURL} }

// Update downloads the dhi/osv tree and publishes its OSV records.
func (u Updater) Update() error {
	source, err := utils.DownloadToTempDir(context.Background(), u.url)
	if err != nil {
		return xerrors.Errorf("failed to download DHI advisories: %w", err)
	}
	defer os.RemoveAll(source) // nolint: errcheck

	return updateFromDir(source, filepath.Join(utils.VulnListDir(), "dhi"))
}

// updateFromDir copies the OSV records found below source into target,
// keeping their year directories. Sidecars and other non-JSON files are skipped.
func updateFromDir(source, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		return xerrors.Errorf("failed to create vuln-list directory: %w", err)
	}
	staging, err := os.MkdirTemp(filepath.Dir(target), ".dhi-")
	if err != nil {
		return xerrors.Errorf("failed to create staging directory: %w", err)
	}
	defer os.RemoveAll(staging)

	seen := make(map[string]string)
	err = filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".json" {
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

		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		// An advisory is published once; a second copy would be silently overwritten
		// or applied twice downstream.
		if previous, ok := seen[record.ID]; ok {
			return xerrors.Errorf("duplicate DHI advisory %s in %s and %s", record.ID, previous, rel)
		}
		seen[record.ID] = rel

		dst := filepath.Join(staging, rel)
		if err = os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
			return err
		}
		return os.WriteFile(dst, raw, 0600)
	})
	if err != nil {
		return xerrors.Errorf("failed to stage DHI advisories: %w", err)
	}
	if len(seen) == 0 {
		return xerrors.New("no DHI OSV advisories found under dhi/osv")
	}

	if err = os.RemoveAll(target); err != nil {
		return xerrors.Errorf("failed to remove previous DHI advisories: %w", err)
	}
	if err = os.Rename(staging, target); err != nil {
		return xerrors.Errorf("failed to publish DHI advisories: %w", err)
	}
	return nil
}
