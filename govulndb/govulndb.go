package govulndb

import (
	"encoding/json"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"

	"golang.org/x/xerrors"

	pb "gopkg.in/cheggaaa/pb.v1"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	baseURL     = "https://storage.googleapis.com/go-vulndb"
	goVulnDBDir = "go"
	concurrency = 5
	wait        = 0
	retry       = 5
)

func Update() error {
	log.Println("Fetching Go Vulnerability Database...")

	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil {
		return xerrors.Errorf("failed to parse baseURL for go-vulndb: %w", err)
	}
	basePath := parsedBaseURL.Path
	parsedBaseURL.Path = path.Join(parsedBaseURL.Path, "index.json")
	b, err := utils.FetchURL(parsedBaseURL.String(), "", retry)
	if err != nil {
		return xerrors.Errorf("failed to fetch go-vulndb index.json: %w", err)
	}
	parsedBaseURL.Path = basePath
	var vulnerablePackages map[string]string
	if err := json.Unmarshal(b, &vulnerablePackages); err != nil {
		return xerrors.Errorf("failed to decode go-vulndb index.json response: %w", err)
	}
	var urls []string
	for packageName := range vulnerablePackages {
		parsedBaseURL.Path = path.Join(parsedBaseURL.Path, packageName+".json")
		urls = append(urls, parsedBaseURL.String())
		parsedBaseURL.Path = basePath
	}
	responses, err := utils.FetchConcurrently(urls, concurrency, wait, retry)
	if err != nil {
		return xerrors.Errorf("failed to fetch concurrently: %w", err)
	}
	log.Println("Saving Go Vulnerability Database...")
	bar := pb.StartNew(len(responses))
	for _, res := range responses {
		var entries []Entry
		if err := json.Unmarshal(res, &entries); err != nil {
			return xerrors.Errorf("failed to decode go-vulndb response: %w", err)
		}
		if err := save(entries); err != nil {
			return xerrors.Errorf("failed to save go-vulndb entries: %w", err)
		}
		bar.Increment()
	}
	bar.Finish()
	return nil
}

func save(entries []Entry) error {
	for _, entry := range entries {
		cveID := entry.ID
		cveDir := filepath.Join(utils.VulnListDir(), goVulnDBDir, entry.Package.Name)
		if err := os.MkdirAll(cveDir, os.ModePerm); err != nil {
			return err
		}
		filePath := filepath.Join(cveDir, cveID+".json")
		if err := utils.Write(filePath, entry); err != nil {
			return xerrors.Errorf("failed to save go-vulndb detail: %w", err)
		}
	}
	return nil
}
