package nvd

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	jsonpointer "github.com/mattn/go-jsonpointer"
	"golang.org/x/xerrors"
	pb "gopkg.in/cheggaaa/pb.v1"

	"github.com/aquasecurity/vuln-list-update/utils"
)

type NVD struct {
	CVEItems []interface{} `json:"CVE_Items"`
}

const (
	baseURL     = "https://nvd.nist.gov/feeds/json/cve/1.1"
	feedDir     = "feed"
	concurrency = 5
	wait        = 0
	retry       = 5
)

func Update(thisYear int) error {
	lastUpdatedDate, err := utils.GetLastUpdatedDate("nvd")
	if err != nil {
		return err
	}

	var old bool
	var feeds []string
	for _, feed := range []string{"modified", "recent"} {
		lastModifiedDate, err := fetchLastModifiedDate(feed)
		if err != nil {
			return err
		}

		if lastUpdatedDate.After(lastModifiedDate) {
			continue
		}
		feeds = append(feeds, feed)

		duration := lastModifiedDate.Sub(lastUpdatedDate)
		if duration > 24*time.Hour*7 {
			old = true
		}
	}

	if old {
		// Fetch all years
		feeds = []string{}
		for year := 2002; year <= thisYear; year++ {
			feeds = append(feeds, fmt.Sprint(year))
		}
	}

	feedCount := len(feeds)
	if feedCount == 0 {
		return nil
	}

	urls := make([]string, feedCount)
	for i, feed := range feeds {
		url := fmt.Sprintf("%s/nvdcve-1.1-%s.json.gz", baseURL, feed)
		urls[i] = url
	}

	log.Println("Fetching NVD data...")
	responses, err := utils.FetchConcurrently(urls, concurrency, wait, retry)
	if err != nil {
		return xerrors.Errorf("failed to fetch concurrently: %w", err)
	}

	log.Println("Saving NVD data...")
	bar := pb.StartNew(len(responses))
	for _, res := range responses {
		nvd, err := decode(res)
		if err != nil {
			return xerrors.Errorf("failed to decode NVD response: %w", err)
		}

		if err := save(nvd); err != nil {
			return err
		}
		bar.Increment()
	}
	bar.Finish()
	return nil
}

func save(nvd *NVD) error {
	for _, item := range nvd.CVEItems {
		v, err := jsonpointer.Get(item, "/cve/CVE_data_meta/ID")
		if err != nil {
			log.Println(err)
			continue
		}

		cveID, ok := v.(string)
		if !ok {
			log.Println("failed to type assertion")
			continue
		}

		if err = utils.SaveCVEPerYear(filepath.Join(utils.VulnListDir(), feedDir), cveID, item); err != nil {
			return xerrors.Errorf("failed to save NVD CVE detail: %w", err)
		}
	}
	return nil
}

func fetchLastModifiedDate(feed string) (time.Time, error) {
	log.Printf("Fetching NVD metadata(%s)...\n", feed)

	url := fmt.Sprintf("%s/nvdcve-1.1-%s.meta", baseURL, feed)
	res, err := utils.FetchURL(url, "", 5)
	if err != nil {
		return time.Time{}, xerrors.Errorf("fetch error: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewBuffer(res))
	for scanner.Scan() {
		line := scanner.Text()
		s := strings.SplitN(line, ":", 2)
		if len(s) != 2 {
			continue
		}
		if s[0] == "lastModifiedDate" {
			t, err := time.Parse(time.RFC3339, s[1])
			if err != nil {
				return time.Time{}, err
			}
			return t, nil
		}
	}
	return time.Unix(0, 0), nil

}

func decode(b []byte) (*NVD, error) {
	zr, err := gzip.NewReader(bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	nvd := &NVD{}
	err = json.NewDecoder(zr).Decode(nvd)
	if err != nil {
		return nil, err
	}
	return nvd, nil
}
