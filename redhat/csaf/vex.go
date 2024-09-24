package csaf

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/csaf-poc/csaf_distribution/v3/csaf"
	"github.com/klauspost/compress/zstd"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	vexDir  = "csaf-vex"
	retry   = 5
	baseURL = "https://access.redhat.com/security/data/csaf/v2/vex/"
)

type Option func(*Config)

func WithBaseDir(dir string) Option {
	return func(c *Config) { c.baseDir = dir }
}

func WithBaseURL(url *url.URL) Option {
	return func(c *Config) { c.baseURL = url }
}

func WithRetry(retry int) Option {
	return func(c *Config) { c.retry = retry }
}

type Config struct {
	baseDir string
	baseURL *url.URL
	retry   int
}

func NewConfig(opts ...Option) *Config {
	c := Config{
		baseDir: filepath.Join(utils.VulnListDir(), vexDir),
		baseURL: lo.Must(url.Parse(baseURL)),
		retry:   retry,
	}
	for _, o := range opts {
		o(&c)
	}
	return &c
}

func (c *Config) Update() error {
	log.Printf("Removing Red Hat CSAF VEX directory %s", c.baseDir)
	if err := os.RemoveAll(c.baseDir); err != nil {
		return xerrors.Errorf("failed to remove Red Hat CSAF VEX directory: %w", err)
	}

	log.Println("Fetching Red Hat CSAF VEX data...")
	archive, err := c.fetchVEXArchive()
	if err != nil {
		return xerrors.Errorf("failed to fetch VEX archive: %w", err)
	}
	defer os.Remove(archive)

	f, err := os.Open(archive)
	if err != nil {
		return xerrors.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	d, err := zstd.NewReader(f)
	if err != nil {
		return xerrors.Errorf("failed to create zstd reader: %w", err)
	}
	defer d.Close()

	tr := tar.NewReader(d)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return xerrors.Errorf("failed to read tar header: %w", err)
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		advisory, err := c.loadAdvisory(tr)
		if err != nil {
			return xerrors.Errorf("failed to load advisory: %w", err)
		}

		fileName := filepath.Base(hdr.Name)
		cveID := strings.TrimSuffix(fileName, filepath.Ext(fileName))
		if err = utils.SaveCVEPerYear(c.baseDir, cveID, advisory); err != nil {
			return xerrors.Errorf("failed to save advisory: %w", err)
		}
	}

	return nil
}

func (c *Config) fetchVEXArchive() (string, error) {
	// Fetch the latest archive name
	u := c.baseURL.ResolveReference(&url.URL{Path: "archive_latest.txt"})
	log.Printf("  Fetching the latest archive name from %s", u.String())
	b, err := utils.FetchURL(u.String(), "", c.retry)
	if err != nil {
		return "", xerrors.Errorf("failed to fetch URL (%s): %w", u.String(), err)
	}
	archiveName := string(b)

	// Fetch the latest archive
	u = c.baseURL.ResolveReference(&url.URL{Path: archiveName})
	log.Printf("  Fetching the latest archive from %s", u.String())
	b, err = utils.FetchURL(u.String(), "", c.retry)
	if err != nil {
		return "", xerrors.Errorf("failed to fetch URL (%s): %w", u.String(), err)
	}
	out, err := os.CreateTemp("", "csaf_vex_*.tar.zst")
	if err != nil {
		return "", xerrors.Errorf("failed to create temp file: %w", err)
	}
	defer out.Close()

	// Write the archive to a temp file
	if _, err = out.Write(b); err != nil {
		return "", xerrors.Errorf("failed to write to temp file: %w", err)
	}

	return out.Name(), nil
}

// LoadAdvisory loads an advisory from a file.
func (c *Config) loadAdvisory(r io.Reader) (*csaf.Advisory, error) {
	var advisory csaf.Advisory
	if err := json.NewDecoder(r).Decode(&advisory); err != nil {
		return nil, xerrors.Errorf("json decode error: %w", err)
	}
	if err := advisory.Validate(); err != nil {
		return nil, xerrors.Errorf("invalid advisory: %w", err)
	}
	return &advisory, nil
}
