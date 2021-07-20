package utils

import (
	"context"
	"os"

	"github.com/hashicorp/go-getter"
	"golang.org/x/xerrors"
)

func DownloadToTempDir(ctx context.Context, url string) (string, error) {
	tmpDir, err := os.MkdirTemp("", "debian")
	if err != nil {
		return "", xerrors.Errorf("failed to create a temp dir: %w", err)
	}

	pwd, err := os.Getwd()
	if err != nil {
		return "", xerrors.Errorf("unable to get the current dir: %w", err)
	}

	// Build the client
	client := &getter.Client{
		Ctx:     ctx,
		Src:     url,
		Dst:     tmpDir,
		Pwd:     pwd,
		Getters: getter.Getters,
		Mode:    getter.ClientModeAny,
	}

	if err = client.Get(); err != nil {
		return "", xerrors.Errorf("failed to download: %w", err)
	}

	return tmpDir, nil
}
