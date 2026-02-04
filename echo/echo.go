package echo

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	echoDir            = "echo"
	advisoriesURLBase  = "https://advisory.echohq.com"
	advisoriesFilePath = "data.json"
)

type option func(c *Updater)

func WithVulnListDir(v string) option {
	return func(c *Updater) { c.vulnListDir = v }
}

func WithBaseURL(v *url.URL) option {
	return func(c *Updater) { c.baseURL = v }
}

type Updater struct {
	vulnListDir string
	baseURL     *url.URL
}

func NewUpdater(options ...option) *Updater {
	u, _ := url.Parse(advisoriesURLBase)
	updater := &Updater{
		vulnListDir: utils.VulnListDir(),
		baseURL:     u,
	}
	for _, option := range options {
		option(updater)
	}

	return updater
}

func (u *Updater) Update() error {
	dir := filepath.Join(u.vulnListDir, echoDir)
	log.Printf("Remove echo directory %s", dir)
	if err := os.RemoveAll(dir); err != nil {
		return xerrors.Errorf("failed to remove Echo directory: %w", err)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return xerrors.Errorf("Echo mkdir error: %w", err)
	}

	log.Println("Fetching Echo data...")

	url := u.baseURL.JoinPath(advisoriesFilePath)
	data, err := utils.FetchURL(url.String(), "", 2)
	if err != nil {
		return xerrors.Errorf("Failed to fetch Echo advisory file from %s - %s", url.String(), err.Error())
	}

	var advisory Advisory
	if err := json.Unmarshal(data, &advisory); err != nil {
		return xerrors.Errorf("failed to parse Echo advisory json - %s", err.Error())
	}

	for pkgName, cveMap := range advisory {
		pkgFilePath := filepath.Join(dir, fmt.Sprintf("%s.json", pkgName))
		if err := utils.Write(pkgFilePath, cveMap); err != nil {
			return xerrors.Errorf("failed to write pkg %s file to path %s", pkgName, pkgFilePath)
		}
	}
	return nil
}
