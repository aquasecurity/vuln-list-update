package cvrf

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"log"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/cheggaaa/pb"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

var (
	cvrfURL     = "http://ftp.suse.com/pub/projects/security/cvrf/"
	fileRegexp  = regexp.MustCompile(`<a href="(cvrf-(.*?)-.*)">.*`)
	retry       = 5
	concurrency = 20
	wait        = 1
	cvrfDir     = "cvrf"
	suseDir     = "suse"
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
	log.Print("Fetching SUSE data...")

	res, err := utils.FetchURL(c.URL, "", retry)
	if err != nil {
		return xerrors.Errorf("Cannot download SUSE CVRF list: %v", err)
	}

	cvrfUrlsMap := make(map[string][]string)
	scanner := bufio.NewScanner(bytes.NewReader(res))
	for scanner.Scan() {
		line := scanner.Text()
		if match := fileRegexp.FindStringSubmatch(line); len(match) != 0 {
			cvrfUrlsMap[match[2]] = append(cvrfUrlsMap[match[2]], c.URL+match[1])
		}
	}

	for os, urls := range cvrfUrlsMap {
		err = c.update(os, urls)
		if err != nil {
			return xerrors.Errorf("failed Update CVRF: %w", err)
		}
	}
	return nil
}

func (c Config) update(os string, urls []string) error {
	cvrfXmls, err := utils.FetchConcurrently(urls, concurrency, wait, retry)
	if err != nil {
		log.Printf("failed to fetch CVRF data from SUSE. err: %s", err)
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
			return xerrors.Errorf("failed to decode SUSE XML: %w", err)
		}
		cvrfs = append(cvrfs, cv)
	}

	dir := filepath.Join(cvrfDir, suseDir, os)
	log.Printf("Fetching %s CVRF data...", os)
	bar := pb.StartNew(len(cvrfs))
	for _, cvrf := range cvrfs {
		if err = c.saveCvrfPerYear(dir, cvrf.Tracking.ID, cvrf); err != nil {
			return xerrors.Errorf("failed to save CVRF: %w", err)
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}

func (c Config) saveCvrfPerYear(dirName string, cvrfID string, data interface{}) error {
	s := strings.Split(cvrfID, "-")
	if len(s) < 4 {
		log.Printf("invalid CVRF-ID format: %s", cvrfID)
		return nil
	}

	year := strings.Split(s[2], ":")[0]
	if len(year) < 4 {
		log.Printf("invalid CVRF-ID format: %s", cvrfID)
		return nil
	}

	yearDir := filepath.Join(c.VulnListDir, dirName, year)
	fileName := fmt.Sprintf("%s.json", strings.Replace(cvrfID, ":", "-", 1))
	if err := utils.WriteJSON(c.AppFs, yearDir, fileName, data); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}
