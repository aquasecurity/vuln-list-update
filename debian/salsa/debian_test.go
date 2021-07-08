package salsa

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/xerrors"
)

func TestDebianSalsa_getReleases(t *testing.T) {
	type fields struct {
		VulnListDir    string
		oss            map[string]string
		cveToDSA       map[string][]dsa
		PackageData    map[string]map[string]CVERelease
		cloneDirectory string
	}
	releaseFields := fields{
		VulnListDir:    "testdata/got",
		oss:            nil,
		cveToDSA:       nil,
		PackageData:    make(map[string]map[string]CVERelease),
		cloneDirectory: "testdata/fixtures",
	}
	ossData := map[string]string{
		"wheezy":   "7",
		"jessie":   "8",
		"stretch":  "9",
		"buster":   "10",
		"bullseye": "11",
		"sid":      "unstable"}
	dsaDate, err := time.Parse("02 Jan 2006", "10 Jun 2021")
	assert.NoError(t, err, "Date parsing error")
	dsa4930 := dsa{
		name:        "DSA-4930-1",
		date:        dsaDate,
		description: "libwebp - security update",
		cves:        []string{"CVE-2018-25009", "CVE-2018-25010"},
		packages:    []pkg{{release: "buster", name: "libwebp", version: "0.6.1-2+deb10u1", severity: "", statement: "", willNotFix: false, classification: 0, severityClassification: ""}},
	}

	dsaDate, err = time.Parse("02 Jan 2006", "30 Jul 2002")
	assert.NoError(t, err, "Date parsing error")
	dsa136 := dsa{
		name:        "DSA-136",
		date:        dsaDate,
		description: "openssl - multiple remote exploits",
		cves:        []string{"CVE-2002-0655", "CVE-2002-0656"},
		packages:    nil,
	}

	dsaDate, err = time.Parse("02 Jan 2006", "02 Jul 2002")
	assert.NoError(t, err, "Date parsing error")
	dsa135 := dsa{
		name:        "DSA-135",
		date:        dsaDate,
		description: "libapache-mod-ssl -- buffer overflow / DoS",
		cves:        []string{"CVE-2002-0653"},
		packages:    nil,
	}

	dsaDate, err = time.Parse("02 Jan 2006", "09 Jun 2021")
	assert.NoError(t, err, "Date parsing error")

	dla2681 := dsa{
		name:        "DLA-2681-1",
		date:        dsaDate,
		description: "eterm - security update",
		cves:        []string{"CVE-2021-33477"},
		packages:    []pkg{{release: "stretch", name: "eterm", version: "0.9.6-5+deb9u1", severity: "", statement: "", willNotFix: false, classification: 0, severityClassification: ""}},
	}

	dsaDate, err = time.Parse("02 Jan 2006", "02 Jun 2014")
	assert.NoError(t, err, "Date parsing error")
	dla0001 := dsa{
		name:        "DLA-0001-1",
		date:        dsaDate,
		description: "gnutls26 - security update",
		cves:        []string{"CVE-2014-3466"},
		packages:    nil,
	}

	wantCVEtoDSAData := map[string][]dsa{"CVE-2018-25009": {dsa4930}, "CVE-2018-25010": {dsa4930}, "CVE-2002-0655": {dsa136}, "CVE-2002-0656": {dsa136},
		"CVE-2021-33477": {dla2681}, "CVE-2002-0653": {dsa135}, "CVE-2014-3466": {dla0001}}

	tests := []struct {
		name         string
		fields       fields
		wantErr      bool
		wantOss      map[string]string
		wantCVEtoDSA map[string][]dsa
	}{
		{name: "All functions", fields: releaseFields, wantErr: false, wantOss: ossData, wantCVEtoDSA: wantCVEtoDSAData},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			debianCtx := &DebianSalsa{
				VulnListDir:    tt.fields.VulnListDir,
				oss:            tt.fields.oss,
				cveToDSA:       tt.fields.cveToDSA,
				PackageData:    tt.fields.PackageData,
				cloneDirectory: tt.fields.cloneDirectory,
			}
			if err := debianCtx.getReleases(); (err != nil) != tt.wantErr {
				t.Errorf("getReleases() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.wantOss, debianCtx.oss) {
				t.Errorf("oss = %v, wantoss %v", debianCtx.oss, tt.wantOss)
			}
			// Test DSA
			if err := debianCtx.parseDSAs(); (err != nil) != tt.wantErr {
				t.Errorf("parseDSAs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.wantCVEtoDSA, debianCtx.cveToDSA) {
				t.Errorf("cveToDSA = %v, wantCVEtoDSA %v", debianCtx.cveToDSA, tt.wantCVEtoDSA)
			}
			if err := debianCtx.parseCVEs(); (err != nil) != tt.wantErr {
				t.Errorf("Update() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err := debianCtx.writePackages(); (err != nil) != tt.wantErr {
				t.Errorf("writePackages() error = %v, wantErr %v", err, tt.wantErr)
			}
			dir := filepath.Join(debianCtx.VulnListDir, "debian-salsa")
			assert.NoError(t, err, "failed to create temp dir")
			defer os.RemoveAll(debianCtx.VulnListDir)
			err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return xerrors.Errorf("walk error: %w", err)
				}
				if info.IsDir() {
					return nil
				}
				paths := strings.Split(path, string(os.PathSeparator))
				p := filepath.Join(paths[len(paths)-2:]...)
				golden := filepath.Join("testdata", "golden", "debian-salsa", p+".golden")

				want, err := ioutil.ReadFile(golden)
				assert.NoError(t, err, "failed to open the golden file")

				got, err := ioutil.ReadFile(path)
				assert.NoError(t, err, "failed to open the result file")

				if match := assert.Equal(t, string(want), string(got)); !match {
					t.Errorf("want file = %v, got %v", want, got)
				}

				return nil
			})
		})
	}
}
