package utils

import (
	"context"
	"os"

	getter "github.com/hashicorp/go-getter"
	"golang.org/x/xerrors"
)

func DownloadToTempDir(ctx context.Context, src string) (string, error) {
	tmpDir, err := os.MkdirTemp("", "vuln-list-update")
	if err != nil {
		return "", xerrors.Errorf("failed to create a temp dir: %w", err)
	}

	// go-getter doesn't allow destination to exist.It needs to be removed once.
	// https://github.com/hashicorp/go-getter/blob/7b99c311a18a8bb679bc7ff3a830a65029afef9b/module_test.go#L18-L28
	if err = os.RemoveAll(tmpDir); err != nil {
		return "", xerrors.Errorf("failed to remove %s: %w", tmpDir, err)
	}

	if err = download(ctx, src, tmpDir, getter.ClientModeDir); err != nil {
		return "", xerrors.Errorf("download error: %w", err)
	}

	return tmpDir, nil
}

func DownloadToTempFile(ctx context.Context, src string) (string, error) {
	f, err := os.CreateTemp("", "vuln-list-update")
	if err != nil {
		return "", xerrors.Errorf("failed to create a temp file: %w", err)
	}
	if err = f.Close(); err != nil {
		return "", xerrors.Errorf("close error: %w", err)
	}

	if err = download(ctx, src, f.Name(), getter.ClientModeFile); err != nil {
		return "", xerrors.Errorf("download error: %w", err)
	}

	return f.Name(), nil
}

func download(ctx context.Context, src, dst string, mode getter.ClientMode) error {
	pwd, err := os.Getwd()
	if err != nil {
		return xerrors.Errorf("unable to get the current dir: %w", err)
	}

	// Build the client
	client := &getter.Client{
		Ctx:     ctx,
		Src:     src,
		Dst:     dst,
		Pwd:     pwd,
		Getters: getter.Getters,
		Mode:    mode,
	}

	if err = client.Get(); err != nil {
		return xerrors.Errorf("failed to download: %w", err)
	}

	return nil
}
