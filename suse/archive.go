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

// Updater downloads a SUSE security tar archive and saves the advisories it contains.
type Updater struct {
	URL         string
	VulnListDir string
	AppFs       afero.Fs
	Dir         string // directory relative to the vuln-list root, e.g. "cvrf/suse"
	Retries     int

	// OSName returns the OS an advisory file belongs to. Entries with no known OS — other
	// vendors' advisories, LICENSE — are skipped before their content is read.
	OSName func(filename string) (string, bool)
}

// Update walks the archive and saves every advisory returned by parse under Dir/<os>/<year>.
// parse returns an empty advisory ID to skip an entry; a non-nil error aborts the update.
func (u Updater) Update(parse func(filename string, data []byte) (advisoryID string, advisory any, err error)) error {
	// The SUSE server is sometimes unstable, so download the whole archive into
	// memory before processing. Streaming directly from the HTTP response would
	// make it hard to distinguish a mid-transfer disconnection (which surfaces
	// as a truncated tar) from a legitimate parse error. The archive is only a
	// few hundred MB, which fits comfortably in memory on CI runners.
	body, err := utils.FetchURL(u.URL, "", u.Retries)
	if err != nil {
		return xerrors.Errorf("failed to download archive: %w", err)
	}

	decompressed, closeFn, err := decompressArchive(u.URL, body)
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
		osName, ok := u.OSName(filename)
		if !ok {
			continue
		}

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

		advisoryID, advisory, err := parse(filename, data)
		if err != nil {
			return err
		}
		if advisoryID == "" {
			continue
		}

		if err := savePerYear(u.VulnListDir, u.AppFs, filepath.Join(u.Dir, osName), advisoryID, advisory); err != nil {
			return xerrors.Errorf("failed to save advisory: %w", err)
		}
	}
}

func decompressArchive(url string, body []byte) (io.Reader, func() error, error) {
	switch {
	case strings.HasSuffix(url, ".tar.bz2"):
		// The upstream archive is .tar.bz2, which is the only format used in production.
		return bzip2.NewReader(bytes.NewReader(body)), nil, nil
	case strings.HasSuffix(url, ".tar.gz"):
		// Go's compress/bzip2 lacks a Writer, so tests use .tar.gz instead.
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, nil, xerrors.Errorf("failed to decompress gzip: %w", err)
		}
		return gr, gr.Close, nil
	default:
		return nil, nil, xerrors.Errorf("unsupported archive format: %s", url)
	}
}

// savePerYear writes data under dirName/<year>/<id>.json, taking the year from the advisory ID:
// "SUSE-SU-2019:0048-2" -> "cvrf/suse/suse/2019/SUSE-SU-2019-0048-2.json".
// Advisories with an unexpected ID format are skipped.
func savePerYear(vulnListDir string, fs afero.Fs, dirName, advisoryID string, data any) error {
	parts := strings.Split(advisoryID, "-")
	if len(parts) < 4 {
		log.Printf("invalid advisory ID format: %s", advisoryID)
		return nil
	}

	year := strings.Split(parts[2], ":")[0]
	if len(year) < 4 {
		log.Printf("invalid advisory ID format: %s", advisoryID)
		return nil
	}

	yearDir := filepath.Join(vulnListDir, dirName, year)
	fileName := fmt.Sprintf("%s.json", strings.Replace(advisoryID, ":", "-", 1))
	if err := utils.WriteJSON(fs, yearDir, fileName, data); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}
