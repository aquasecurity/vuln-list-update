package fedora

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/cheggaaa/pb"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"
)

const (
	fedoraURL   = "https://bodhi.fedoraproject.org/updates/?type=security&page=%d"
	fedoraDir   = "fedora"
	concurrency = 20
	wait        = 1
	retry       = 10
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
		URL:         fedoraURL,
		AppFs:       afero.NewOsFs(),
		Retry:       retry,
	}
}

func (c Config) Update() error {
	log.Printf("Fetching Fedora")

	dir := filepath.Join(c.VulnListDir, fedoraDir)
	if err := os.RemoveAll(dir); err != nil {
		return xerrors.Errorf("unable to remove fedora directory: %w", err)
	}
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}

	advisories, err := c.listFedoraAdvisories()
	if err != nil {
		return xerrors.Errorf("failed to get Fedora advisories: %w", err)
	}
	bar := pb.StartNew(len(advisories))
	for _, advisory := range advisories {
		if err := c.saveFedoraIDPerYear(fedoraDir, advisory.FedoraID, advisory.Release.IDPrefix, advisory); err != nil {
			return xerrors.Errorf("failed to save FEDORA-UPDATE-ID per year name: %w", err)
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}

func (c Config) listFedoraAdvisories() (advisories []FedoraAdvisory, err error) {
	// Get the first page of the fedora advisory
	url := fmt.Sprintf(c.URL, 1)
	fapJSON, err := utils.FetchURL(url, "", retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch Fefora Advisories: url: %s, err: %w", url, err)
	}
	var fap FedoraAdvisoriesPagenation
	if err = json.Unmarshal(fapJSON, &fap); err != nil {
		return nil, xerrors.Errorf("failed to unmarshal Fedora advisories pagenations: %w", err)
	}
	advisories = append(advisories, fap.FedoraAdvisories...)

	// Get the second and subsequent pages of fedora advisory
	var urls []string
	for page := 2; page <= fap.Pages; page++ {
		urls = append(urls, fmt.Sprintf(c.URL, page))
	}
	fapJSONs, err := utils.FetchConcurrently(urls, concurrency, wait, retry)
	if err != nil {
		log.Printf("failed to fetch cve data from RedHat. err: %s", err)
	}

	for _, fapJSON := range fapJSONs {
		var fap FedoraAdvisoriesPagenation
		if err = json.Unmarshal(fapJSON, &fap); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal fedora advisories pagenations: %w", err)
		}
		advisories = append(advisories, fap.FedoraAdvisories...)
	}

	return
}

func (c Config) saveFedoraIDPerYear(dirName string, fedoraID, idPrefix string, data interface{}) error {
	s := strings.Split(strings.TrimPrefix(fedoraID, idPrefix+"-"), "-")
	if len(s) != 2 {
		log.Printf("invalid Fedora-ID: %s", fedoraID)
		return xerrors.Errorf("invalid Fedora-ID format: %s", fedoraID)
	}

	yearDir := filepath.Join(c.VulnListDir, dirName, s[0])
	if err := c.AppFs.MkdirAll(yearDir, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to create dir: %w", err)
	}

	filePath := filepath.Join(yearDir, fmt.Sprintf("%s.json", fedoraID))

	fs := utils.NewFs(c.AppFs)
	if err := fs.WriteJSON(filePath, data); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}
