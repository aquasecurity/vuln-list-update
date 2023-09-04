package oval

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
	"strings"

	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/cheggaaa/pb/v3"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"
)

const (
	ovalDir = "oval"

	urlFormat = "https://rdb.altlinux.org/api/errata/export/oval/%s"
	retry     = 5

	branchURL = "https://rdb.altlinux.org/api/errata/export/oval/branches"
)

type Config struct {
	VulnListDir string
	URLFormat   string
	BranchURL   string
	AppFs       afero.Fs
	Retry       int
}

func NewConfig() Config {
	return Config{
		VulnListDir: utils.VulnListDir(),
		URLFormat:   urlFormat,
		BranchURL:   branchURL,
		AppFs:       afero.NewOsFs(),
		Retry:       retry,
	}
}

func (c Config) Update() error {
	dirPath := filepath.Join(c.VulnListDir, ovalDir)
	log.Printf("Remove ALT OVAL directory %s", dirPath)
	if err := os.RemoveAll(dirPath); err != nil {
		return xerrors.Errorf("failed to remove ALT directory: %w", err)
	}

	log.Println("Fetching ALT OVAL data...")
	ovalPaths, err := c.fetchOvalPaths()
	if err != nil {
		return xerrors.Errorf("failed to get oval file paths: %w", err)
	}
	for _, ovalPath := range ovalPaths {
		log.Printf("Fetching %s", ovalPath)
		if err = c.updateOVAL(ovalPath); err != nil {
			return xerrors.Errorf("failed to update ALT OVAL: %w", err)
		}
	}
	return nil
}

func (c Config) fetchOvalPaths() ([]string, error) {
	res, err := utils.FetchURL(c.BranchURL, "", c.Retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch branches: %w", err)
	}
	var branches Branches
	err = json.Unmarshal(res, &branches)
	if err != nil {
		return nil, xerrors.Errorf("failed to unmarshal branches.json: %w", err)
	}
	var paths []string
	for _, b := range branches.Branches {
		paths = append(paths, fmt.Sprintf(c.URLFormat, b))
	}
	return paths, nil
}

func (c Config) updateOVAL(ovalPath string) error {
	res, err := utils.FetchURL(ovalPath, "", c.Retry)
	if err != nil {
		return err
	}
	r, err := zip.NewReader(bytes.NewReader(res), int64(len(res)))
	if err != nil {
		return err
	}
	splits := strings.Split(ovalPath, "/")
	platform := splits[len(splits)-1]

	bar := pb.StartNew(len(r.File))
	for _, f := range r.File {
		var oval OVAL
		rc, err := f.Open()
		if err != nil {
			return err
		}
		content, err := io.ReadAll(rc)
		if err != nil {
			rc.Close()
			return err
		}
		err = xml.Unmarshal(content, &oval)
		if err != nil {
			rc.Close()
			return err
		}
		splits = strings.Split(f.Name, ".")
		if strings.Contains(f.Name, "ALTPU-20221161") {
			println("")
		}
		dirPath := filepath.Join(c.VulnListDir, ovalDir, platform, splits[0])
		if err = utils.WriteJSON(c.AppFs, dirPath, "tests.json", oval.Tests); err != nil {
			rc.Close()
			return xerrors.Errorf("failed to write tests: %w", err)
		}

		if err = utils.WriteJSON(c.AppFs, dirPath, "objects.json", oval.Objects); err != nil {
			rc.Close()
			return xerrors.Errorf("failed to write objects: %w", err)
		}

		if err = utils.WriteJSON(c.AppFs, dirPath, "states.json", oval.States); err != nil {
			rc.Close()
			return xerrors.Errorf("failed to write states: %w", err)
		}

		if err = utils.WriteJSON(c.AppFs, dirPath, "definitions.json", oval.Definitions); err != nil {
			rc.Close()
			return xerrors.Errorf("failed to write definitions: %w", err)
		}
		bar.Increment()
		rc.Close()
	}
	bar.Finish()
	return nil
}
