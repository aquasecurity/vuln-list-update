package cwe

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

type CWEConfig struct {
	url        string
	retryTimes int
	cweDir     string
}

const (
	cweURL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
)

func NewCWEConfig() CWEConfig {
	return NewCWEWithConfig(cweURL, filepath.Join(utils.VulnListDir(), "cwe"), 5)
}

func NewCWEWithConfig(url, path string, retryTimes int) CWEConfig {
	return CWEConfig{
		url:        url,
		retryTimes: retryTimes,
		cweDir:     path,
	}
}

func (c CWEConfig) Update() error {
	log.Println("Fetching CWE data...")
	data, err := utils.FetchURL(c.url, "", c.retryTimes)
	if err != nil {
		return xerrors.Errorf("failed to fetch cwe data: %w", err)
	}

	b, err := c.unzip(data)
	if err != nil {
		return err
	}

	var wc WeaknessCatalog
	if wc, err = xmlToJSON(b); err != nil {
		return err
	}

	if err := os.MkdirAll(c.cweDir, os.ModePerm); err != nil {
		return xerrors.Errorf("unable to create cwe directory: %w", err)
	}

	for _, w := range wc.Weaknesses.Weakness {
		b, err := json.MarshalIndent(w, "", " ")
		if err != nil {
			log.Printf("unable to marshal: %d, err: %s\n", w.ID, err)
			continue
		}
		if err := c.saveFile(b, fmt.Sprintf("CWE-%d.json", w.ID)); err != nil {
			return err
		}
	}

	return nil
}

func (c CWEConfig) saveFile(b []byte, fileType string) error {
	if err := os.WriteFile(filepath.Join(c.cweDir, fileType), b, 0600); err != nil {
		return xerrors.Errorf("failed to write %s file: %w", fileType, err)
	}
	return nil

}

func (c CWEConfig) unzip(data []byte) ([]byte, error) {
	zipReader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, xerrors.Errorf("unable to initialize zip: %w", err)
	}

	if len(zipReader.File) > 1 {
		return nil, xerrors.Errorf("invalid CWE zip: too many files in archive")
	}

	b, err := readZipFile(zipReader.File[0])
	if err != nil {
		return nil, xerrors.Errorf("unable to read zip archive: %w", err)
	}
	return b, nil
}

func readZipFile(zf *zip.File) ([]byte, error) {
	f, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func xmlToJSON(b []byte) (WeaknessCatalog, error) {
	var wc WeaknessCatalog
	if err := xml.Unmarshal(b, &wc); err != nil {
		return WeaknessCatalog{}, err
	}
	return wc, nil
}
