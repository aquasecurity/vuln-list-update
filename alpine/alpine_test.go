package alpine

import (
	"encoding/json"
	"io/ioutil"
	"path"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePkgVerRel(t *testing.T) {
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
		},
		{
			file:   "testdata/APKBUILD_multicves",
			pkgVer: "2.6.8",
			pkgRel: "1",
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			content, err := ioutil.ReadFile(v.file)
			if err != nil {
				t.Fatalf("ReadAll() error: %v", err)
			}

			pkgVer, pkgRel, err := parsePkgVerRel(string(content))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if pkgVer != v.pkgVer {
				t.Errorf("pkgVer: got %s, want %s", pkgVer, v.pkgVer)
			}

			if pkgRel != v.pkgRel {
				t.Errorf("pkgRel: got %s, want %s", pkgRel, v.pkgRel)
			}
		})
	}
}

func TestParseSecFixes(t *testing.T) {
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

			secFixes, err := parseSecFixes(string(content))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(secFixes, v.secFixes) {
				t.Errorf("secFixes: got %v, want %v", secFixes, v.secFixes)
			}
		})
	}
}

func TestShouldOverwrite(t *testing.T) {

	t.Run("happy and sad paths with valid versions", func(t *testing.T) {
		issuedAdvisory := Advisory{
			IssueID:         100,
			VulnerabilityID: "CVE-2100-0001",
			Release:         "1.0",
			Package:         "testpackage",
			Repository:      "main",
			//Subject:         "test advisory",
			Description: "for testing only",
		}

		testCases := []struct {
			name             string
			currentVersion   string
			fixedVersion     string
			expctedOverwrite bool
		}{
			{
				name:             "issued advisory should overwrite existing one",
				currentVersion:   "1.0.0",
				fixedVersion:     "1.2.0",
				expctedOverwrite: true,
			},
			{
				name:             "issued advisory should NOT overwrite existing one",
				currentVersion:   "1.0.0",
				fixedVersion:     "0.9.0",
				expctedOverwrite: false,
			},
		}

		for _, tc := range testCases {
			f, _ := ioutil.TempFile("", "TestShouldOverwrite_happy_sad")
			issuedAdvisory.FixedVersion = tc.fixedVersion
			b, _ := json.Marshal(&issuedAdvisory)
			_, _ = f.Write(b)
			defer f.Close()

			assert.Equal(t, tc.expctedOverwrite, shouldOverwrite(f.Name(), tc.currentVersion), tc.name)
		}
	})

	// TODO: Why should this overwrite with invalid advisory json?
	t.Run("invalid advisory json", func(t *testing.T) {
		f, _ := ioutil.TempFile("", "TestShouldOverwrite_invalid_json")
		_, _ = f.Write([]byte(`badjsonhere`))
		defer f.Close()

		assert.Equal(t, false, shouldOverwrite(f.Name(), "doesnt matter"), "invalid advisory json")

	})

	// TODO: Why should this not overwrite with a subject in advisory json?
	t.Run("non empty subject advisory", func(t *testing.T) {
		f, _ := ioutil.TempFile("", "TestShouldOverwrite_subject_advisory_json")
		b, _ := json.Marshal(&Advisory{
			Subject: "non empty subject",
		})
		_, _ = f.Write(b)
		defer f.Close()

		assert.True(t, shouldOverwrite(f.Name(), "doesnt matter"), "subject advisory json")

	})

	t.Run("invalid new advisory version", func(t *testing.T) {
		f, _ := ioutil.TempFile("", "TestShouldOverwrite_invalid_version_json_new")
		b, _ := json.Marshal(&Advisory{
			FixedVersion: "badversionhere",
		})
		_, _ = f.Write(b)
		defer f.Close()

		assert.False(t, shouldOverwrite(f.Name(), "doesnt matter"), "invalid new advisory version")

	})

	t.Run("invalid current advisory version", func(t *testing.T) {
		f, _ := ioutil.TempFile("", "TestShouldOverwrite_invalid_version_json_current")
		b, _ := json.Marshal(&Advisory{
			FixedVersion: "1.0.0",
		})
		_, _ = f.Write(b)
		defer f.Close()

		assert.False(t, shouldOverwrite(f.Name(), "badversionhere"), "invalid current advisory version")

	})
}
