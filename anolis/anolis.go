package anolis

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	pb "github.com/cheggaaa/pb/v3"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	anolisDir = "anolis"
	urlFormat = "https://anas.openanolis.cn/api/data/OVAL/anolis-%s.oval.xml"
	retry     = 5
)

var (
	AnolisOvalVersion = []string{"7", "7_els", "8", "23"}
)
var (
	ErrInvalidANSAID = xerrors.New("invalid ANSA ID")
)

type Config struct {
	VulnListDir string
	URLs        map[string]string
	AppFs       afero.Fs
	Retry       int
}

func NewConfig() Config {
	urls := map[string]string{}
	for _, version := range AnolisOvalVersion {
		urls[version] = fmt.Sprintf(urlFormat, version)
	}
	return Config{
		VulnListDir: utils.VulnListDir(),
		URLs:        urls,
		AppFs:       afero.NewOsFs(),
		Retry:       retry,
	}
}

func (c *Config) Update() error {
	for version, url := range c.URLs {
		if version == "7_els" {
			version = "7"
		}
		log.Printf("Fetching Anolis OVAL data from %s...\n", url)

		// Fetch the XML file from the URL
		res, err := utils.FetchURL(url, "", c.Retry)
		if err != nil {
			return xerrors.Errorf("failed to fetch Anolis OVAL: %w", err)
		}

		var ov Oval
		err = xml.NewDecoder(bytes.NewReader(res)).Decode(&ov)
		if err != nil {
			return xerrors.Errorf("failed to decode Anolis OVAL XML: %w", err)
		}

		dir := filepath.Join(c.VulnListDir, anolisDir, version)
		bar := pb.StartNew(len(ov.Definitions))

		for _, def := range ov.Definitions {
			def.Metadata.Title = strings.TrimSpace(def.Metadata.Title)
			def.Metadata.Description = strings.TrimSpace(def.Metadata.Description)

			var ansaID string
			for _, ref := range def.Metadata.References {
				if strings.HasPrefix(ref.RefID, "ANSA") {
					ansaID = strings.TrimSpace(ref.RefID)
					break
				}
			}

			if ansaID == "" {
				log.Printf("Invalid ANSA ID: %s\n", ansaID)
				continue
			}

			if err = c.SaveANSAPerYear(dir, ansaID, def); err != nil {
				if err == ErrInvalidANSAID {
					log.Printf("Invalid ANSA ID: %s\n", ansaID)
					continue
				}
				return xerrors.Errorf("failed to save ANSA per year: %w", err)
			}
			bar.Increment()
		}
		bar.Finish()
	}

	return nil
}

func (c Config) SaveANSAPerYear(dirName string, ansaID string, data interface{}) error {
	s := strings.Split(ansaID, ":")
	if len(s) < 2 {
		return ErrInvalidANSAID
	}

	year := strings.Split(s[0], "-")[1] // Extract the year part from "ANSA-2024"
	yearDir := filepath.Join(dirName, year)

	if err := c.AppFs.MkdirAll(yearDir, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to create directory: %w", err)
	}
	jsonFileName := fmt.Sprintf("%s.json", ansaID)

	if err := utils.WriteJSON(c.AppFs, yearDir, jsonFileName, data); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}

	return nil
}
