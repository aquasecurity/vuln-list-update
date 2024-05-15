package openeuler

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"log"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/cheggaaa/pb"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

var (
	cvrfURL      = "https://repo.openeuler.org/security/data/cvrf"
	retry        = 5
	concurrency  = 20
	wait         = 1
	openeulerDir = "openeuler"
)

type Config struct {
	VulnListDir string
	URL         string
	AppFs       afero.Fs
	Retry       int
}

func NewConfig() Config {
	return Config{
		VulnListDir: utils.VulnListDir(),
		URL:         cvrfURL,
		AppFs:       afero.NewOsFs(),
		Retry:       retry,
	}
}

func (c Config) Update() error {
	log.Print("Fetching openEuler CVRF data...")
	u, err := url.Parse(c.URL)
	if err != nil {
		return xerrors.Errorf("failed to parse openEuler URL: %w", err)
	}
	baseURL := u.Path
	u.Path = path.Join(baseURL, "index.txt")

	res, err := utils.FetchURL(u.String(), "", c.Retry)
	if err != nil {
		return xerrors.Errorf("Cannot download openEuler CVRF list: %v", err)
	}
	cvrfUrlsMap := make(map[string][]string)
	scanner := bufio.NewScanner(bytes.NewReader(res))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "/", 2)
		u.Path = path.Join(baseURL, line)
		cvrfUrlsMap[parts[0]] = append(cvrfUrlsMap[parts[0]], u.String())
	}

	for year, urls := range cvrfUrlsMap {
		err = c.update(year, urls)
		if err != nil {
			return xerrors.Errorf("failed Update openEuler CVRF: %w", err)
		}
	}

	return nil
}

func (c Config) update(year string, urls []string) error {
	cvrfXmls, err := utils.FetchConcurrently(urls, concurrency, wait, c.Retry)
	if err != nil {
		log.Printf("failed to fetch CVRF data from repo.openEuler.org, err: %s", err)
	}

	var cvrfs []Cvrf
	for _, cvrfXml := range cvrfXmls {
		var cv Cvrf
		if len(cvrfXml) == 0 {
			log.Println("empty CVRF xml")
			continue
		}

		if !utf8.Valid(cvrfXml) {
			log.Println("invalid UTF-8")
			cvrfXml = []byte(strings.ToValidUTF8(string(cvrfXml), ""))
		}

		err = xml.Unmarshal(cvrfXml, &cv)
		if err != nil {
			return xerrors.Errorf("failed to decode openEuler cvrf XML: %w", err)
		}
		cvrfs = append(cvrfs, cv)
	}

	dir := filepath.Join(openeulerDir, year)
	log.Printf("Fetching openEuler CVRF %s data into %s ...", year, dir)

	bar := pb.StartNew(len(cvrfs))
	for _, cvrf := range cvrfs {
		yearDir := filepath.Join(c.VulnListDir, dir)
		if err = c.saveCvrf(yearDir, cvrf); err != nil {
			return xerrors.Errorf("failed to save CVRF: %w", err)
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}

func (c Config) saveCvrf(dirName string, cvrf Cvrf) error {
	cvrfID := cvrf.Tracking.ID
	substrings := strings.Split(cvrfID, "-")
	if len(substrings) < 4 {
		log.Printf("invalid CVRF-ID format: %s", cvrfID)
		return nil
	}

	fileName := fmt.Sprintf("%s.json", cvrfID)
	if err := utils.WriteJSON(c.AppFs, dirName, fileName, cvrf); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}
