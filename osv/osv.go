// Package osv provides generic OSV (Open Source Vulnerability) format specification
// and reusable vulnerability data processing functionality.
//
// This package contains:
// - OSV format type definitions based on https://ossf.github.io/osv-schema
// - Generic data processing logic that can work with any OSV-compliant data source
// - Ecosystem configuration for flexible data source management
//
// This is intended as a reusable library that other packages can use to implement
// specific OSV data sources (e.g., osv.dev, seal).
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

// Database represents a generic OSV vulnerability database that can process
// vulnerability data from any OSV-compliant source.
type Database struct {
	baseDir    string               // Base directory for storing vulnerability data
	ecosystems map[string]Ecosystem // Map of ecosystem name to configuration
}

// NewDatabase creates a new generic OSV database instance.
// baseDir is the root directory where vulnerability data will be stored.
// ecosystems maps ecosystem names to their configuration (storage directory and source URL).
func NewDatabase(baseDir string, ecosystems map[string]Ecosystem) Database {
	return Database{
		baseDir:    baseDir,
		ecosystems: ecosystems,
	}
}

func (db *Database) Update() error {
	ctx := context.Background()
	for name, ecosystem := range db.ecosystems {
		log.Printf("Updating OSV %s advisories", name)

		tempDir, err := utils.DownloadToTempDir(ctx, ecosystem.URL)
		if err != nil {
			return xerrors.Errorf("failed to download %s: %w", ecosystem.URL, err)
		}

		err = filepath.WalkDir(tempDir, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			} else if d.IsDir() {
				return nil
			}
			f, err := os.Open(path)
			if err != nil {
				return xerrors.Errorf("file open error (%s): %w", path, err)
			}

			var parsed OSV
			if err = json.NewDecoder(f).Decode(&parsed); err != nil {
				return xerrors.Errorf("unable to parse json %s: %w", path, err)
			}

			filePath := filepath.Join(db.baseDir, ecosystem.Dir, parsed.Affected[0].Package.Name, fmt.Sprintf("%s.json", parsed.ID))
			if err = utils.Write(filePath, parsed); err != nil {
				return xerrors.Errorf("failed to write file: %w", err)
			}
			return nil
		})
		if err != nil {
			return xerrors.Errorf("walk error: %w", err)
		}
	}
	return nil
}
