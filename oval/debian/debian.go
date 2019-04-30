package debian

import (
	"encoding/xml"
	"fmt"
	"log"
	"path/filepath"

	"github.com/knqyf263/vuln-list-update/utils"
	"golang.org/x/xerrors"
	pb "gopkg.in/cheggaaa/pb.v1"
)

const (
	ovalDir   = "oval"
	debianDir = "debian"
	urlFormat = "https://www.debian.org/security/oval/oval-definitions-%s.xml"
)

var (
	debianName = map[string]string{
		"7":  "wheezy",
		"8":  "jessie",
		"9":  "stretch",
		"10": "buster",
	}
)

type OVAL struct {
	DefinitionID    string
	Title           string
	AffectedProduct string
}

func Update() error {
	log.Println("Fetching Debian data...")
	for _, release := range debianName {
		url := fmt.Sprintf(urlFormat, release)

		res, err := utils.FetchURL(url, "", 5)
		if err != nil {
			return xerrors.Errorf("failed to fetch Debian OVAL: %w", err)
		}

		log.Printf("Updating Debian %s data...\n", release)
		ovalroot := Root{}
		if err = xml.Unmarshal(res, &ovalroot); err != nil {
			return xerrors.Errorf("failed to unmarshal Debian OVAL XML: %w", err)
		}

		dir := filepath.Join(ovalDir, debianDir, release)
		bar := pb.StartNew(len(ovalroot.Definitions.Definitions))
		for _, def := range ovalroot.Definitions.Definitions {
			if err = utils.SaveCVEPerYear(dir, def.Metadata.Title, def); err != nil {
				return err
			}
			bar.Increment()
		}
		bar.Finish()
	}
	return nil
}
