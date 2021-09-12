package utils

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/spf13/afero"
	"golang.org/x/xerrors"
)

func WriteJSON(fs afero.Fs, dir, fileName string, data interface{}) error {
	if err := fs.MkdirAll(dir, os.ModePerm); err != nil {
		return xerrors.Errorf("unable to create a directory: %w", err)
	}

	filePath := filepath.Join(dir, fileName)
	f, err := fs.Create(filePath)
	if err != nil {
		return xerrors.Errorf("unable to open %s: %w", filePath, err)
	}
	defer f.Close()

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal JSON: %w", err)
	}

	if _, err = f.Write(b); err != nil {
		return xerrors.Errorf("failed to save a file: %w", err)
	}
	return nil
}
