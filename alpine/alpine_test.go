package alpine

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"path"
	"reflect"
	"testing"

	"golang.org/x/xerrors"

	"github.com/stretchr/testify/assert"
)

type MockGitConfig struct {
	cloneorpull  func(string, string) (map[string]struct{}, error)
	remotebranch func(string) ([]string, error)
	checkout     func(string, string) error
}

func (mgc MockGitConfig) CloneOrPull(a string, b string) (map[string]struct{}, error) {
	if mgc.cloneorpull != nil {
		return mgc.cloneorpull(a, b)
	}
	return map[string]struct{}{}, nil
}

func (mgc MockGitConfig) RemoteBranch(a string) ([]string, error) {
	if mgc.remotebranch != nil {
		return mgc.remotebranch(a)
	}
	return []string{}, nil
}

func (mgc MockGitConfig) Checkout(a string, b string) error {
	if mgc.checkout != nil {
		return mgc.checkout(a, b)
	}
	return nil
}

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

	t.Run("invalid advisory json", func(t *testing.T) {
		f, _ := ioutil.TempFile("", "TestShouldOverwrite_invalid_json")
		_, _ = f.Write([]byte(`badjsonhere`))
		defer f.Close()

		assert.Equal(t, true, shouldOverwrite(f.Name(), "doesnt matter"), "invalid advisory json")

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

func TestWalkApkBuild(t *testing.T) {
	advisories, err := walkApkBuild("testdata", "1.0.0")
	assert.NoError(t, err)
	assert.Equal(t, []Advisory{
		{IssueID: 0, VulnerabilityID: "CVE-2019-7572", Release: "1.0.0", Package: "testdata", Repository: ".", FixedVersion: "1.2.15-r11", Subject: "", Description: ""},
		{IssueID: 0, VulnerabilityID: "CVE-2019-7574", Release: "1.0.0", Package: "testdata", Repository: ".", FixedVersion: "1.2.15-r11", Subject: "", Description: ""}}, advisories)
}

func TestBuildAdvisories(t *testing.T) {
	secFixes := map[string][]string{
		"2.6.8-r0": {"CVE-2019-10894"},
		"2.6.5-r0": {"CVE_2019-5910 (+ some extra in parens)"},
	}

	assert.Equal(t, []Advisory{
		{IssueID: 0, VulnerabilityID: "CVE-2019-10894", Release: "1.0.0", Package: "testpkg", Repository: "testrepo", FixedVersion: "2.6.8-r0", Subject: "", Description: ""},
		{IssueID: 0, VulnerabilityID: "CVE-2019-5910", Release: "1.0.0", Package: "testpkg", Repository: "testrepo", FixedVersion: "2.6.5-r0", Subject: "", Description: ""}},
		buildAdvisories(secFixes, "1.0.0", "testpkg", "testrepo"))
}

func TestUpdate(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		assert.NoError(t, Update(MockGitConfig{
			remotebranch: func(s string) (strings []string, e error) {
				return []string{"origin/branch1-stable", "origin/branch2", "origin/branch3"}, nil
			},
		}))
	})

	t.Run("invalid branch name", func(t *testing.T) {
		assert.NoError(t, Update(MockGitConfig{
			remotebranch: func(s string) (strings []string, e error) {
				return []string{"badbranch-stable"}, nil
			},
		}))
	})

	t.Run("git clone fails", func(t *testing.T) {
		assert.Equal(t, xerrors.Errorf("failed to clone alpine repository: %w", errors.New("failed clone operation")).Error(),
			Update(MockGitConfig{
				cloneorpull: func(s string, s2 string) (i map[string]struct{}, e error) {
					return nil, errors.New("failed clone operation")
				},
			}).Error(),
		)
	})
	t.Run("git fails to show remote branches", func(t *testing.T) {
		assert.Equal(t, xerrors.Errorf("failed to show branches: %w", errors.New("failed to show remote branch")).Error(),
			Update(MockGitConfig{
				remotebranch: func(s string) (strings []string, e error) {
					return []string{}, errors.New("failed to show remote branch")
				},
			}).Error(),
		)
	})
	t.Run("git fails to checkout branch", func(t *testing.T) {
		assert.Equal(t, xerrors.Errorf("error in git checkout: %w", errors.New("failed to checkout branch")).Error(),
			Update(MockGitConfig{
				checkout: func(s string, s2 string) error {
					return errors.New("failed to checkout branch")
				},
			}).Error(),
		)
	})

	t.Run("git checkout of a particular branch fails", func(t *testing.T) {
		assert.Equal(t, "error in git checkout: failed to checkout branch", Update(MockGitConfig{
			remotebranch: func(s string) (strings []string, e error) {
				return []string{"origin/branch1-stable", "origin/branch2", "origin/branch3"}, nil
			},
			checkout: func(s string, branch string) error {
				switch branch {
				case "master":
					return errors.New("failed to checkout branch")
				case "origin/branch1-stable":
					return errors.New("failed to checkout branch")
				}
				return nil
			},
		}).Error())
	})
}
