package csaf

import (
	"archive/tar"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	csaflib "github.com/csaf-poc/csaf_distribution/v3/csaf"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	csafArchiveURL = "https://ftp.suse.com/pub/projects/security/csaf.tar.bz2"
	csafDir        = "csaf"
	suseDir        = "suse"
	retries        = 5
)

var fileRegexp = regexp.MustCompile(`^(suse-su|opensuse-su)-`)

type Config struct {
	VulnListDir string
	URL         string
	AppFs       afero.Fs
}

// archiveEntry is a single JSON document from the SUSE CSAF tar archive.
type archiveEntry struct {
	Filename string
	Data     []byte
}

func NewConfig() Config {
	return Config{
		VulnListDir: utils.VulnListDir(),
		URL:         csafArchiveURL,
		AppFs:       afero.NewOsFs(),
	}
}

func (c Config) Update() error {
	log.Print("Fetching SUSE CSAF archive...")

	return walkArchive(c.URL, retries, fileRegexp, func(e archiveEntry) error {
		osName, err := osNameFromFilename(e.Filename)
		if err != nil {
			log.Printf("skip %s: %v", e.Filename, err)
			return nil
		}

		var adv csaflib.Advisory
		if err := json.Unmarshal(e.Data, &adv); err != nil {
			log.Printf("skip invalid CSAF json (%s): %v", e.Filename, err)
			return nil
		}

		if err := adv.Validate(); err != nil {
			log.Printf("skip invalid CSAF advisory (%s): %v", e.Filename, err)
			return nil
		}

		if adv.Document == nil || adv.Document.Tracking == nil || adv.Document.Tracking.ID == nil {
			log.Printf("skip advisory without tracking id (%s)", e.Filename)
			return nil
		}

		dir := filepath.Join(csafDir, suseDir, osName)
		if err := c.savePerYear(dir, string(*adv.Document.Tracking.ID), adv); err != nil {
			return xerrors.Errorf("failed to save CSAF: %w", err)
		}
		return nil
	})
}

func osNameFromFilename(filename string) (string, error) {
	match := fileRegexp.FindStringSubmatch(filename)
	if len(match) < 2 {
		return "", fmt.Errorf("unexpected filename")
	}
	switch match[1] {
	case "suse-su":
		return "suse", nil
	case "opensuse-su":
		return "opensuse", nil
	default:
		return "", fmt.Errorf("unknown prefix %q", match[1])
	}
}

func (c Config) savePerYear(dirName, advisoryID string, data any) error {
	s := strings.Split(advisoryID, "-")
	if len(s) < 4 {
		log.Printf("invalid advisory ID format: %s", advisoryID)
		return nil
	}

	year := strings.Split(s[2], ":")[0]
	if len(year) < 4 {
		log.Printf("invalid advisory ID format: %s", advisoryID)
		return nil
	}

	yearDir := filepath.Join(c.VulnListDir, dirName, year)
	fileName := fmt.Sprintf("%s.json", strings.Replace(advisoryID, ":", "-", 1))
	if err := utils.WriteJSON(c.AppFs, yearDir, fileName, data); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}

func walkArchive(url string, retries int, nameRegexp *regexp.Regexp, handler func(archiveEntry) error) error {
	body, err := utils.FetchURL(url, "", retries)
	if err != nil {
		return xerrors.Errorf("failed to download archive: %w", err)
	}

	decompressed, err := decompressArchive(url, body)
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
		if !strings.HasSuffix(filename, ".json") {
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
			log.Printf("empty json: %s", filename)
			continue
		}
		if !utf8.Valid(data) {
			log.Printf("invalid UTF-8: %s", filename)
			data = []byte(strings.ToValidUTF8(string(data), ""))
		}

		if err := handler(archiveEntry{Filename: filename, Data: data}); err != nil {
			return err
		}
	}
}

func decompressArchive(url string, body []byte) (io.Reader, error) {
	switch {
	case strings.HasSuffix(url, ".tar.bz2"):
		return bzip2.NewReader(bytes.NewReader(body)), nil
	case strings.HasSuffix(url, ".tar.gz"):
		return gzip.NewReader(bytes.NewReader(body))
	default:
		return nil, xerrors.Errorf("unsupported archive format: %s", url)
	}
}
