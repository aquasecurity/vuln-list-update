package utils

import (
	"encoding/json"

	"golang.org/x/xerrors"

	"github.com/spf13/afero"
)

type Fs struct {
	AppFs afero.Fs
}

func NewFs(appFs afero.Fs) Fs {
	return Fs{AppFs: appFs}
}

func (fs Fs) WriteJSON(filePath string, data interface{}) error {
	f, err := fs.AppFs.Create(filePath)
	if err != nil {
		return xerrors.Errorf("unable to open a file: %w", err)
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
