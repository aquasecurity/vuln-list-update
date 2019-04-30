package alpine

import (
	"io/ioutil"
	"path"
	"reflect"
	"testing"
)

func TestParseApkBuild(t *testing.T) {
	vectors := []struct {
		file     string // Test input file
		pkgVer   string
		pkgRel   string
		secFixes map[string][]string
	}{
		{
			file:   "testdata/APKBUILD_plain",
			pkgVer: "3.0.19",
			pkgRel: "0",
			secFixes: map[string][]string{
				"3.0.19-r0": {"CVE-2019-11234", "CVE-2019-11235"},
			},
		},
		{
			file:   "testdata/APKBUILD_multicves",
			pkgVer: "2.6.8",
			pkgRel: "1",
			secFixes: map[string][]string{
				"2.6.8-r0": {"CVE-2019-10894", "CVE-2019-10895", "CVE-2019-10896", "CVE-2019-10899", "CVE-2019-10901", "CVE-2019-10903"},
				"2.6.7-r0": {"CVE-2019-9208", "CVE-2019-9209", "CVE-2019-9214"},
				"2.6.6-r0": {"CVE-2019-5717", "CVE-2019-5718", "CVE-2019-5719", "CVE-2019-5721"},
			},
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			content, err := ioutil.ReadFile(v.file)
			if err != nil {
				t.Fatalf("ReadAll() error: %v", err)
			}

			pkgVer, pkgRel, secFixes, err := parseApkBuild(string(content))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if pkgVer != v.pkgVer {
				t.Errorf("pkgVer: got %s, want %s", pkgVer, v.pkgVer)
			}

			if pkgRel != v.pkgRel {
				t.Errorf("pkgRel: got %s, want %s", pkgRel, v.pkgRel)
			}
			if !reflect.DeepEqual(secFixes, v.secFixes) {
				t.Errorf("secFixes: got %v, want %v", secFixes, v.secFixes)
			}
		})
	}
}
