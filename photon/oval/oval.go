package oval

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	pb "github.com/cheggaaa/pb/v3"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	ovalURLFormat = "https://packages.broadcom.com/photon/photon_oval_definitions/com.vmware.phsa-photon%s.xml.gz"
	photonOvalDir = "photon-oval"
	retry         = 5
)

var photonVersions = []string{"1", "2", "3", "4", "5"}

type Config struct {
	VulnListDir string
	URLFormat   string
	AppFs       afero.Fs
	Retry       int
}

func NewConfig() Config {
	return Config{
		VulnListDir: utils.VulnListDir(),
		URLFormat:   ovalURLFormat,
		AppFs:       afero.NewOsFs(),
		Retry:       retry,
	}
}

func (c Config) Update() error {
	log.Printf("Fetching Photon OVAL")

	for _, ver := range photonVersions {
		if err := c.UpdateVersion(ver); err != nil {
			return xerrors.Errorf("failed to update Photon OVAL for version %s: %w", ver, err)
		}
	}

	return nil
}

func (c Config) UpdateVersion(photonVer string) error {
	url := fmt.Sprintf(c.URLFormat, photonVer)
	res, err := utils.FetchURL(url, "", c.Retry)
	if err != nil {
		return xerrors.Errorf("failed to fetch Photon OVAL: %w", err)
	}

	gr, err := gzip.NewReader(bytes.NewReader(res))
	if err != nil {
		return xerrors.Errorf("failed to decompress Photon OVAL: %w", err)
	}
	defer gr.Close()

	var ov OvalDefinitions
	if err = xml.NewDecoder(gr).Decode(&ov); err != nil {
		return xerrors.Errorf("failed to decode Photon OVAL XML: %w", err)
	}

	osVer := photonVer + ".0"
	bar := pb.StartNew(len(ov.Definitions))
	for _, def := range ov.Definitions {
		def.Title = strings.TrimSpace(def.Title)
		def.Description = strings.TrimSpace(def.Description)
		normalizeRefURLs(def.References)

		phsaID, err := PhsaIDFromRef(def.References, def.Issued.Date)
		if err != nil {
			log.Printf("invalid PHSA reference in %q: %v\n", def.Title, err)
			bar.Increment()
			continue
		}

		if err = c.savePHSA(osVer, phsaID, def); err != nil {
			return xerrors.Errorf("failed to save PHSA: %w", err)
		}

		bar.Increment()
	}
	bar.Finish()

	return nil
}

func (c Config) savePHSA(osVer, phsaID string, def Definition) error {
	dir := filepath.Join(c.VulnListDir, photonOvalDir, osVer)
	fileName := fmt.Sprintf("%s.json", phsaID)
	if err := utils.WriteJSON(c.AppFs, dir, fileName, def); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}

// normalizeRefURLs fixes a known typo in Photon OVAL ref_urls where the wiki path segment
// "Security-Updates-" should be "Security-Update-" (without trailing 's').
func normalizeRefURLs(refs []Reference) {
	for i, ref := range refs {
		refs[i].URI = strings.Replace(ref.URI, "/Security-Updates-", "/Security-Update-", 1)
	}
}

// PhsaIDFromRef extracts a filesystem-safe PHSA advisory ID from definition references and issued date.
// It finds the reference with source="PHSA" and parses its ref_id together with the issued year.
// E.g. ref_id="PHSA:00001:5.0:20", issuedDate="2023-06-07" → "PHSA-2023-5.0-20"
func PhsaIDFromRef(refs []Reference, issuedDate string) (string, error) {
	if len(issuedDate) < 4 {
		return "", xerrors.Errorf("invalid issued date: %q", issuedDate)
	}
	year := issuedDate[:4]
	for _, ref := range refs {
		if ref.Source != "PHSA" {
			continue
		}
		// Format: PHSA:{sequence}:{photon_ver}:{advisory_number}
		parts := strings.Split(ref.ID, ":")
		if len(parts) != 4 || parts[0] != "PHSA" {
			return "", xerrors.Errorf("unexpected PHSA ref_id format: %s", ref.ID)
		}
		return "PHSA-" + year + "-" + parts[2] + "-" + parts[3], nil
	}
	return "", xerrors.New("no PHSA source reference found")
}
