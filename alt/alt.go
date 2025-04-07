package alt

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

	"github.com/cheggaaa/pb/v3"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	altDir = "oval"

	branchURL     = "https://rdb.altlinux.org/api/errata/export/oval/%s"
	branchListURL = "https://rdb.altlinux.org/api/errata/export/oval/branches"

	retry = 5
)

type Config struct {
	VulnListDir   string
	BranchURL     string
	BranchListURL string
	AppFs         afero.Fs
	Retry         int
}

func NewConfig() Config {
	return Config{
		VulnListDir:   utils.VulnListDir(),
		BranchURL:     branchURL,
		BranchListURL: branchListURL,
		AppFs:         afero.NewOsFs(),
		Retry:         retry,
	}
}

type BranchList struct {
	Length   int
	Branches []string
}

func (c Config) Update() error {
	dirPath := filepath.Join(c.VulnListDir, altDir)
	log.Printf("Remove ALT's OVAL directoty: %s", dirPath)
	if err := os.RemoveAll(dirPath); err != nil {
		return xerrors.Errorf("failed to remove ALT's OVAL directory: %w", err)
	}

	log.Println("Fetching ALT's OVAL branch list...")
	branchList, err := c.fetchBranchList()
	if err != nil {
		return err
	}

	for _, branch := range branchList.Branches {
		log.Printf("Fetching ALT's OVAL branch: %s", branch)
		if err := c.updateOVAL(branch); err != nil {
			return err
		}
	}

	return nil
}

func (c Config) fetchBranchList() (BranchList, error) {
	resp, err := utils.FetchURL(c.BranchListURL, "", c.Retry)
	if err != nil {
		return BranchList{}, xerrors.Errorf("failed to get ALT's OVAL branch list: %w", err)
	}

	var branchList BranchList
	if err := json.Unmarshal(resp, &branchList); err != nil {
		return BranchList{}, xerrors.Errorf("failed to unmarshal branch list JSON response: %w", err)
	}

	return branchList, nil
}

func (c Config) updateOVAL(branch string) error {
	ovalURL := fmt.Sprintf(c.BranchURL, branch)

	resp, err := utils.FetchURL(ovalURL, "", c.Retry)
	if err != nil {
		return xerrors.Errorf("failed to get ALT's OVAL branch archive: %w", err)
	}

	reader, err := zip.NewReader(bytes.NewReader(resp), int64(len(resp)))
	if err != nil {
		return xerrors.Errorf("failed to init zip reader: %w", err)
	}

	pbar := pb.StartNew(len(reader.File))
	for _, file := range reader.File {
		var oval OVALDefinitions
		rc, err := file.Open()
		if err != nil {
			return xerrors.Errorf("failed to open file: %w", err)
		}
		content, err := io.ReadAll(rc)
		if err != nil {
			rc.Close()
			return xerrors.Errorf("failed to read file content: %w", err)
		}

		err = xml.Unmarshal(content, &oval)
		if err != nil {
			rc.Close()
			return xerrors.Errorf("failed to unmarshal ALT's OVAL xml: %w", err)
		}

		ovalName := strings.TrimSuffix(file.Name, ".xml")
		ovalPath := filepath.Join(c.VulnListDir, altDir, branch, ovalName)

		if err := utils.WriteJSON(c.AppFs, ovalPath, "tests.json", oval.Tests); err != nil {
			rc.Close()
			return xerrors.Errorf("failed to write tests.json: %w", err)
		}

		if err := utils.WriteJSON(c.AppFs, ovalPath, "objects.json", oval.Objects); err != nil {
			rc.Close()
			return xerrors.Errorf("failed to write objects.json: %w", err)
		}

		if err = utils.WriteJSON(c.AppFs, ovalPath, "states.json", oval.States); err != nil {
			rc.Close()
			return xerrors.Errorf("failed to write states: %w", err)
		}

		if err = utils.WriteJSON(c.AppFs, ovalPath, "definitions.json", oval.Definitions); err != nil {
			rc.Close()
			return xerrors.Errorf("failed to write definitions: %w", err)
		}

		pbar.Increment()
		rc.Close()
	}

	pbar.Finish()
	return nil
}
