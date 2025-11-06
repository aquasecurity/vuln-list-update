package eoldates

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"path/filepath"

	"github.com/samber/lo"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const fullEOLDatesURL = "https://endoflife.date/api/v1/products/full"

var (
	supportedOSes = []string{
		"almalinux",
		"alpine-linux",
		"amazon-linux",
		"azure-linux",   // endoflife.date doesn't support this OS
		"mariner-linux", // endoflife.date doesn't support this OS
		"centos",
		"chainguard", // Chainguard doesn't have OS versions (there is no EOL dates)
		"debian",
		"echo",    // echo doesn't have OS versions (there is no EOL dates)
		"minimos", // minimos doesn't have OS versions (there is no EOL dates)
		"opensuse",
		"oracle-linux",
		"photon",
		"rhel",
		"rocky-linux",
		"sles",
		"ubuntu",
		"wolfi-linux", // wolfi doesn't have OS versions (there is no EOL dates)
		"suse-linux-micro",
	}

	missedOSes = map[string][]Release{
		// cf. https://techcommunity.microsoft.com/blog/azuretoolsblog/announcement-of-migrating-to-azure-linux-3-0-for-azure-cli/4419582
		"azure-linux": {
			{
				Name:    "3.0",
				EOLFrom: "2027-07-31", // No EOL date available, set to a far future date
			},
		},
		// cf. https://devblogs.microsoft.com/java/important-updates-to-container-images-of-microsoft-build-of-openjdk/
		"mariner-linux": {
			{
				Name:    "1.0",
				EOLFrom: "2023-11-31",
			},
			{
				Name:    "2.0",
				EOLFrom: "2025-07-31",
			},
		},
	}
)

type Config struct {
	url           string
	vulnListDir   string
	supportedOSes []string
	missedOSes    map[string][]Release
}

type option func(*Config)

func WithURL(url string) option {
	return func(c *Config) {
		c.url = url
	}
}

func WithVulnListDir(dir string) option {
	return func(c *Config) {
		c.vulnListDir = dir
	}
}

func WithMissedOses(oses map[string][]Release) option {
	return func(c *Config) {
		c.missedOSes = oses
	}
}

func NewConfig(opts ...option) *Config {
	c := &Config{
		url:           fullEOLDatesURL,
		vulnListDir:   utils.VulnListDir(),
		supportedOSes: supportedOSes,
		missedOSes:    missedOSes,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

func (c Config) Update() error {
	eolData, err := c.fetchEOLData()
	if err != nil {
		return xerrors.Errorf("failed to fetch EOL data: %w", err)
	}

	osReleases := c.osReleases(eolData)

	// Fill missed OSes
	osReleases = lo.Assign(c.missedOSes, osReleases)

	if err = c.saveEOLDates(osReleases); err != nil {
		return xerrors.Errorf("failed to save EOL dates: %w", err)
	}

	return nil
}

func (c Config) fetchEOLData() (EOLData, error) {
	log.Printf("Fetching EOL data from %s", c.url)
	resp, err := http.Get(c.url)
	if err != nil {
		return EOLData{}, xerrors.Errorf("unable to get full EOL dates: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return EOLData{}, xerrors.Errorf("unable to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return EOLData{}, xerrors.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var eolData EOLData
	if err = json.Unmarshal(body, &eolData); err != nil {
		return EOLData{}, xerrors.Errorf("unable to parse JSON: %w", err)
	}
	return eolData, nil
}

func (c Config) osReleases(eolData EOLData) map[string][]Release {
	osReleases := make(map[string][]Release)
	for _, result := range eolData.Results {
		if slices.Contains(c.supportedOSes, result.Name) {
			osReleases[result.Name] = result.Releases
		}
	}
	return osReleases
}

func (c Config) saveEOLDates(osReleases map[string][]Release) error {
	filePath := filepath.Join(c.vulnListDir, "eoldates", "eoldates.json")
	err := utils.Write(filePath, osReleases)
	if err != nil {
		return xerrors.Errorf("failed to write EOL dates file: %w", err)
	}
	return nil
}
