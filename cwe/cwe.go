package cwe

import (
	"archive/zip"
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/aquasecurity/vuln-list-update/utils"
	"golang.org/x/xerrors"
)

type CWEConfig struct {
	url        string
	retryTimes int
	cweDir     string
}

func NewCWEConfig() CWEConfig {
	return NewCWEWithConfig("https://cwe.mitre.org/data/xml/cwec_latest.xml.zip", filepath.Join(utils.VulnListDir(), "cwe"), 5)
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

	zipReader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return xerrors.Errorf("unable to initialize zip: %w", err)
	}

	if len(zipReader.File) > 1 {
		return xerrors.Errorf("invalid CWE zip: too many files in archive")
	}

	b, err := readZipFile(zipReader.File[0])
	if err != nil {
		return xerrors.Errorf("unable to read zip archive: %w", err)
	}

	if err := os.MkdirAll(c.cweDir, os.ModePerm); err != nil {
		return xerrors.Errorf("unable to create cwe directory: %w", err)
	}

	if err := ioutil.WriteFile(filepath.Join(c.cweDir, "cwe.xml"), b, 0600); err != nil {
		return xerrors.Errorf("failed to cwe write file: %w", err)
	}
	return nil
}

func readZipFile(zf *zip.File) ([]byte, error) {
	f, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ioutil.ReadAll(f)
}
