package utils

import (
	"context"
	"os"

	getter "github.com/hashicorp/go-getter"
	"golang.org/x/xerrors"
)

func DownloadToTempDir(ctx context.Context, url string) (string, error) {
	tmpDir, err := os.MkdirTemp("", "vuln-list-update")
	if err != nil {
		return "", xerrors.Errorf("failed to create a temp dir: %w", err)
	}

	// go-getter doesn't allow destination to exist.It needs to be removed onc
	// https://github.com/hashicorp/go-getter/blob/7b99c311a18a8bb679bc7ff3a830a65029afef9b/module_test.go#L18-L28
	if err = os.RemoveAll(tmpDir); err != nil {

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
