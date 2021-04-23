package govulndb

import (
	"encoding/json"
	"fmt"
	"log"

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
	log.Println("Fetching GoVulnDB data...")

	b, err := utils.FetchURL(baseURL+"/index.json", "", retry)
	if err != nil {
		return err
	}
	var vulnerablePackages map[string]string
	if err := json.Unmarshal(b, &vulnerablePackages); err != nil {
		return xerrors.Errorf("failed to decode goVulnDB index.json response: %w", err)
	}
	urls := make([]string, len(vulnerablePackages))
	i := 0
	for packageName := range vulnerablePackages {
		url := fmt.Sprintf("%s/%s.json", baseURL, packageName)
		urls[i] = url
		i++
	}
	responses, err := utils.FetchConcurrently(urls, concurrency, wait, retry)
	if err != nil {
		return xerrors.Errorf("failed to fetch concurrently: %w", err)
	}
	log.Println("Saving GoVulnDB data...")
	bar := pb.StartNew(len(responses))
	for _, res := range responses {
		var entries []Entry
		if err := json.Unmarshal(res, &entries); err != nil {
			return xerrors.Errorf("failed to decode goVulnDB response: %w", err)
		}
		if err := save(entries); err != nil {
			return err
		}
		bar.Increment()
	}
	bar.Finish()
	return nil
}

func save(entries []Entry) error {
	for _, entry := range entries {
		cveID := entry.ID
		if err := utils.SaveCVEPerYear(fmt.Sprintf("%s/%s", goVulnDBDir, entry.Package.Name), cveID, entry); err != nil {
			return xerrors.Errorf("failed to save NVD CVE detail: %w", err)
		}
	}
	return nil
}
