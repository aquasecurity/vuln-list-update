package suse

import (
	"archive/tar"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

// TarEntry is a single regular file from a SUSE security tar archive.
type TarEntry struct {
	Filename string
	Data     []byte
}

// WalkTarArchive downloads a .tar.bz2 (or .tar.gz in tests) archive and invokes
// handler for each regular file entry.
func WalkTarArchive(url string, retries int, handler func(TarEntry) error) error {
	body, err := utils.FetchURL(url, "", retries)
	if err != nil {
		return xerrors.Errorf("failed to download archive: %w", err)
	}

	decompressed, closeFn, err := decompressArchive(url, body)
	if err != nil {
		return err
	}
	if closeFn != nil {
		defer closeFn()
	}

	tr := tar.NewReader(decompressed)
	for {
		hdr, err := tr.Next()
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case err != nil:
			return xerrors.Errorf("failed to read tar entry: %w", err)
		case hdr.Typeflag != tar.TypeReg:
			continue
		}

		filename := filepath.Base(hdr.Name)
		data, err := io.ReadAll(tr)
		if err != nil {
			return xerrors.Errorf("failed to read tar entry data: %w", err)
		}
		if len(data) == 0 {
			log.Printf("empty file: %s", filename)
			continue
		}
		if !utf8.Valid(data) {
			log.Printf("invalid UTF-8: %s", filename)
			data = []byte(strings.ToValidUTF8(string(data), ""))
		}

		if err := handler(TarEntry{Filename: filename, Data: data}); err != nil {
			return err
		}
	}
}

func decompressArchive(url string, body []byte) (io.Reader, func() error, error) {
	switch {
	case strings.HasSuffix(url, ".tar.bz2"):
		return bzip2.NewReader(bytes.NewReader(body)), nil, nil
	case strings.HasSuffix(url, ".tar.gz"):
		// .tar.gz is only used in tests; production archives are .tar.bz2.
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, nil, xerrors.Errorf("failed to decompress gzip: %w", err)
		}
		return gr, gr.Close, nil
	default:
		return nil, nil, xerrors.Errorf("unsupported archive format: %s", url)
	}
}

// SavePerYear writes advisory data under dirName/<year>/<id>.json.
func SavePerYear(vulnListDir string, fs afero.Fs, dirName, advisoryID string, data any) error {
	parts := strings.Split(advisoryID, "-")
	if len(parts) < 4 {
		return fmt.Errorf("invalid advisory ID format: %s", advisoryID)
	}

	year := strings.Split(parts[2], ":")[0]
	if len(year) < 4 {
		return fmt.Errorf("invalid advisory ID format: %s", advisoryID)
	}

	yearDir := filepath.Join(vulnListDir, dirName, year)
	fileName := fmt.Sprintf("%s.json", strings.Replace(advisoryID, ":", "-", 1))
	if err := utils.WriteJSON(fs, yearDir, fileName, data); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}
