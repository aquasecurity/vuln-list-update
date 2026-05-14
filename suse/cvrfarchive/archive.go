// Package cvrfarchive walks SUSE CVRF tar archives published at
// http://ftp.suse.com/pub/projects/security/. It hides the
// download/decompress/tar plumbing so feed-specific code only needs
// to handle XML decoding and persistence.
package cvrfarchive

import (
	"archive/tar"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"io"
	"log"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

// Entry is a single XML document extracted from a SUSE CVRF archive.
// Data is guaranteed to be valid UTF-8 (invalid bytes are stripped).
type Entry struct {
	Filename string
	Data     []byte
}

// Walk downloads a SUSE CVRF archive from url, decompresses it
// (bzip2 or gzip, detected by the URL suffix) and invokes handler
// for every .xml entry whose base name matches nameRegexp.
// Non-regular tar entries, empty files and non-XML files are skipped;
// invalid UTF-8 byte sequences are stripped from the data.
func Walk(url string, retries int, nameRegexp *regexp.Regexp, handler func(Entry) error) error {
	// The SUSE server is sometimes unstable, so download the whole archive into
	// memory before processing. Streaming directly from the HTTP response would
	// make it hard to distinguish a mid-transfer disconnection (which surfaces
	// as a truncated tar) from a legitimate parse error. The archive is only a
	// few hundred MB, which fits comfortably in memory on CI runners.
	body, err := utils.FetchURL(url, "", retries)
	if err != nil {
		return xerrors.Errorf("failed to download archive: %w", err)
	}

	decompressed, err := decompress(url, body)
	if err != nil {
		return err
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
		if !strings.HasSuffix(filename, ".xml") {
			continue
		}
		if nameRegexp != nil && !nameRegexp.MatchString(filename) {
			continue
		}

		data, err := io.ReadAll(tr)
		if err != nil {
			return xerrors.Errorf("failed to read tar entry data: %w", err)
		}
		if len(data) == 0 {
			log.Printf("empty xml: %s", filename)
			continue
		}
		if !utf8.Valid(data) {
			log.Printf("invalid UTF-8: %s", filename)
			data = []byte(strings.ToValidUTF8(string(data), ""))
		}

		if err := handler(Entry{Filename: filename, Data: data}); err != nil {
			return err
		}
	}
}

func decompress(url string, body []byte) (io.Reader, error) {
	switch {
	case strings.HasSuffix(url, ".tar.bz2"):
		// The upstream archive is .tar.bz2, which is the only format used in production.
		return bzip2.NewReader(bytes.NewReader(body)), nil
	case strings.HasSuffix(url, ".tar.gz"):
		// Go's compress/bzip2 lacks a Writer, so tests use .tar.gz instead.
		return gzip.NewReader(bytes.NewReader(body))
	default:
		return nil, xerrors.Errorf("unsupported archive format: %s", url)
	}
}
