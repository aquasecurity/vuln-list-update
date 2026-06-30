package bottlerocket

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	retry = 3

	bottlerocketDir = "bottlerocket"
	updateInfoURL   = "https://advisories.bottlerocket.aws/updateinfo.xml.gz"
)

type Config struct {
	url         string
	vulnListDir string
}

type option func(*Config)

func WithURL(url string) option {
	return func(c *Config) {
		c.url = url
	}
}

func WithVulnListDir(vulnListDir string) option {
	return func(c *Config) {
		c.vulnListDir = vulnListDir
	}
}

func NewConfig(opts ...option) *Config {
	config := &Config{
		url:         updateInfoURL,
		vulnListDir: utils.VulnListDir(),
	}
	for _, opt := range opts {
		opt(config)
	}
	return config
}

func (c *Config) Update() error {
	log.Println("Fetching Bottlerocket security advisories...")

	dir := filepath.Join(c.vulnListDir, bottlerocketDir)
	if err := os.RemoveAll(dir); err != nil {
		return xerrors.Errorf("unable to remove bottlerocket directory: %w", err)
	}
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}

	updates, err := fetchUpdateInfo(c.url)
	if err != nil {
		return xerrors.Errorf("failed to fetch Bottlerocket security advisories: %w", err)
	}

	bar := pb.StartNew(len(updates.Updates))
	for _, update := range updates.Updates {
		filePath := filepath.Join(dir, fmt.Sprintf("%s.json", update.ID))
		if err := utils.Write(filePath, update); err != nil {
			return xerrors.Errorf("failed to write Bottlerocket advisory: %w", err)
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}

func fetchUpdateInfo(url string) (*UpdateInfo, error) {
	res, err := utils.FetchURL(url, "", retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch updateinfo.xml.gz: %w", err)
	}

	r, err := gzip.NewReader(bytes.NewReader(res))
	if err != nil {
		return nil, xerrors.Errorf("failed to decompress updateinfo: %w", err)
	}
	defer r.Close()

	var updateInfo UpdateInfo
	if err := xml.NewDecoder(r).Decode(&updateInfo); err != nil {
		return nil, xerrors.Errorf("failed to decode updateinfo XML: %w", err)
	}

	return &updateInfo, nil
}
