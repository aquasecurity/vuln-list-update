package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aquasecurity/vuln-list-update/oval/redhat"
	"github.com/aquasecurity/vuln-list-update/utils"
)

func main() {
	cve := make(map[string]bool)
	ovalDir := utils.VulnListDir() + "/oval/redhat"
	if errWalk := filepath.Walk(ovalDir, func(path string, info os.FileInfo, _ error) error {
		if info.IsDir() {
			return nil
		}
		if strings.HasPrefix(info.Name(), "CVE-") {
			cveID := strings.Replace(info.Name(), ".json", "", 1)
			cve[cveID] = true
			return nil
		}
		content, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		var rhsa redhat.Definition
		err = json.Unmarshal(content, &rhsa)
		if err != nil {
			return err
		}
		for _, c := range rhsa.Advisory.Cves {
			cve[c.CveID] = true
		}
		return nil
	}); errWalk != nil {
		log.Fatal(errWalk)
	}

	var missingCVEs []string
	redHatDir := utils.VulnListDir() + "/redhat"
	if errWalk := filepath.Walk(redHatDir, func(path string, info os.FileInfo, _ error) error {
		if info.IsDir() {
			return nil
		}
		cveID := strings.Replace(info.Name(), ".json", "", 1)
		yearStr := strings.Split(cveID, "-")[1]
		year, _ := strconv.Atoi(yearStr)
		if year < 2011 {
			return nil
		}
		if _, ok := cve[cveID]; !ok {
			missingCVEs = append(missingCVEs, cveID)
		}
		return nil
	}); errWalk != nil {
		log.Fatal(errWalk)
	}
	fmt.Println(strings.Join(missingCVEs, ", "))
}
