package alpine_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/alpine"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockGitConfig struct {
	mock.Mock
}

func (mgc *MockGitConfig) CloneOrPull(a string, b string, c string) (map[string]struct{}, error) {
	args := mgc.Called(a, b, c)
	return args.Get(0).(map[string]struct{}), args.Error(1)
}

func (mgc *MockGitConfig) RemoteBranch(a string) ([]string, error) {
	args := mgc.Called(a)
	return args.Get(0).([]string), args.Error(1)
}

func (mgc *MockGitConfig) Checkout(a string, b string) error {
	args := mgc.Called(a, b)
	return args.Error(0)
}

func TestParsePkgVerRel(t *testing.T) {
	vectors := []struct {
		file     string // Test input file
		pkgVer   string
		pkgRel   string
		secFixes map[string][]string
	}{
		{
			file:   "testdata/aports/main/freeradius/APKBUILD",
			pkgVer: "3.0.19",
			pkgRel: "0",
		},
		{
			file:   "testdata/aports/main/wireshark/APKBUILD",
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

			pkgVer, pkgRel, err := alpine.ParsePkgVerRel(&alpine.Config{}, string(content))
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
			file:   "testdata/aports/main/freeradius/APKBUILD",
			pkgVer: "3.0.19",
			pkgRel: "0",
			secFixes: map[string][]string{
				"3.0.19-r0": {"CVE-2019-11234", "CVE-2019-11235"},
			},
		},
		{
			file:   "testdata/aports/main/wireshark/APKBUILD",
			pkgVer: "2.6.8",
			pkgRel: "1",
			secFixes: map[string][]string{
				"2.6.8-r0": {"CVE-2019-10894", "CVE-2019-10895", "CVE-2019-10896", "CVE-2019-10899", "CVE-2019-10901", "CVE-2019-10903"},
				"2.6.7-r0": {"CVE-2019-9208", "CVE-2019-9209", "CVE-2019-9214"},
				"2.6.6-r0": {"CVE-2019-5717", "CVE-2019-5718", "CVE-2019-5719", "CVE-2019-5721"},
			},
		},
		{
			file:   "testdata/aports/main/libssh2/APKBUILD",
			pkgVer: "1.9.0",
			pkgRel: "1",
			secFixes: map[string][]string{
				"1.9.0-r1": {"CVE-2019-17498"},
				"1.9.0-r0": {"CVE-2019-13115"},
			},
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			content, err := ioutil.ReadFile(v.file)
			if err != nil {
				t.Fatalf("ReadAll() error: %v", err)
			}

			secFixes, err := alpine.ParseSecFixes(&alpine.Config{}, string(content))
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
	testCases := []struct {
		name             string
		currentVersion   string
		issuedAdvisory   interface{}
		expctedOverwrite bool
	}{
		{
			name:           "issued advisory should overwrite existing one with valid version",
			currentVersion: "1.0.0",
			issuedAdvisory: alpine.Advisory{
				IssueID:         0,
				VulnerabilityID: "CVE-2100-0001",
				Release:         "1.0",
				Package:         "testpackage",
				Repository:      "main",
				FixedVersion:    "1.2.0",
				Description:     "for testing only",
			},
			expctedOverwrite: true,
		},
		{
			name:           "issued advisory should overwrite existing one with valid version having a suffix",
			currentVersion: "1.1_beta1",
			issuedAdvisory: alpine.Advisory{
				IssueID:         0,
				VulnerabilityID: "CVE-2100-0001",
				Release:         "1.0",
				Package:         "testpackage",
				Repository:      "main",
				FixedVersion:    "1.1",
				Description:     "for testing only",
			},
			expctedOverwrite: true,
		},
		{
			name:           "issued advisory should NOT overwrite existing one with valid version",
			currentVersion: "1.0.0",
			issuedAdvisory: alpine.Advisory{
				IssueID:         0,
				VulnerabilityID: "CVE-2100-0001",
				Release:         "1.0",
				Package:         "testpackage",
				Repository:      "main",
				FixedVersion:    "0.9.0",
				Description:     "for testing only",
			},
			expctedOverwrite: false,
		},
		{
			name:             "invalid advisory json",
			currentVersion:   "1.0.0",
			issuedAdvisory:   []byte(`badjsonhere`),
			expctedOverwrite: true,
		},
		{
			name:           "empty fixed version",
			currentVersion: "1.0.0",
			issuedAdvisory: alpine.Advisory{
				Subject: "non empty subject",
			},
			expctedOverwrite: true,
		},
		{
			name:           "invalid old advisory version",
			currentVersion: "1.0.0",
			issuedAdvisory: alpine.Advisory{
				Subject:      "non empty subject",
				Package:      "test",
				FixedVersion: "invalid",
			},
			expctedOverwrite: false,
		},
		{
			name:           "invalid current advisory version",
			currentVersion: "invalid",
			issuedAdvisory: alpine.Advisory{
				Subject:      "non empty subject",
				Package:      "test",
				FixedVersion: "1.0.0",
			},
			expctedOverwrite: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := ioutil.TempFile("", "TestShouldOverwrite_happy_sad")
			defer os.Remove(f.Name())
			b, _ := json.Marshal(tc.issuedAdvisory)
			_, _ = f.Write(b)

			assert.Equal(t, tc.expctedOverwrite, alpine.ShouldOverwrite(&alpine.Config{}, f.Name(), tc.currentVersion), tc.name)
			assert.NoError(t, f.Close())
		})
	}
}

func TestWalkApkBuild(t *testing.T) {
	advisories, err := alpine.WalkApkBuild(&alpine.Config{}, "testdata/aports", "1.0.0")
	assert.NoError(t, err)
	assert.ElementsMatch(t, []alpine.Advisory{
		{FixedVersion: "1.2.15-r11", VulnerabilityID: "CVE-2019-7572", Release: "1.0.0", Package: "sdl", Repository: "main"},
		{FixedVersion: "1.2.15-r11", VulnerabilityID: "CVE-2019-7574", Release: "1.0.0", Package: "sdl", Repository: "main"},

		{FixedVersion: "2.6.8-r0", VulnerabilityID: "CVE-2019-10894", Release: "1.0.0", Package: "wireshark", Repository: "main"},
		{FixedVersion: "2.6.8-r0", VulnerabilityID: "CVE-2019-10895", Release: "1.0.0", Package: "wireshark", Repository: "main"},
		{FixedVersion: "2.6.8-r0", VulnerabilityID: "CVE-2019-10896", Release: "1.0.0", Package: "wireshark", Repository: "main"},
		{FixedVersion: "2.6.8-r0", VulnerabilityID: "CVE-2019-10899", Release: "1.0.0", Package: "wireshark", Repository: "main"},
		{FixedVersion: "2.6.8-r0", VulnerabilityID: "CVE-2019-10901", Release: "1.0.0", Package: "wireshark", Repository: "main"},
		{FixedVersion: "2.6.8-r0", VulnerabilityID: "CVE-2019-10903", Release: "1.0.0", Package: "wireshark", Repository: "main"},

		{FixedVersion: "2.6.7-r0", VulnerabilityID: "CVE-2019-9208", Release: "1.0.0", Package: "wireshark", Repository: "main"},
		{FixedVersion: "2.6.7-r0", VulnerabilityID: "CVE-2019-9209", Release: "1.0.0", Package: "wireshark", Repository: "main"},
		{FixedVersion: "2.6.7-r0", VulnerabilityID: "CVE-2019-9214", Release: "1.0.0", Package: "wireshark", Repository: "main"},

		{FixedVersion: "2.6.6-r0", VulnerabilityID: "CVE-2019-5717", Release: "1.0.0", Package: "wireshark", Repository: "main"},
		{FixedVersion: "2.6.6-r0", VulnerabilityID: "CVE-2019-5718", Release: "1.0.0", Package: "wireshark", Repository: "main"},
		{FixedVersion: "2.6.6-r0", VulnerabilityID: "CVE-2019-5719", Release: "1.0.0", Package: "wireshark", Repository: "main"},
		{FixedVersion: "2.6.6-r0", VulnerabilityID: "CVE-2019-5721", Release: "1.0.0", Package: "wireshark", Repository: "main"},

		{FixedVersion: "3.0.19-r0", VulnerabilityID: "CVE-2019-11234", Release: "1.0.0", Package: "freeradius", Repository: "main"},
		{FixedVersion: "3.0.19-r0", VulnerabilityID: "CVE-2019-11235", Release: "1.0.0", Package: "freeradius", Repository: "main"},

		{FixedVersion: "1.9.0-r0", VulnerabilityID: "CVE-2019-13115", Release: "1.0.0", Package: "libssh2", Repository: "main"},
		{FixedVersion: "1.9.0-r1", VulnerabilityID: "CVE-2019-17498", Release: "1.0.0", Package: "libssh2", Repository: "main"},

		{FixedVersion: "1.7.3-r0", VulnerabilityID: "CVE-2019-9917", Release: "1.0.0", Package: "znc", Repository: "community"},
		{FixedVersion: "1.7.1-r0", VulnerabilityID: "CVE-2018-14055", Release: "1.0.0", Package: "znc", Repository: "community"},
		{FixedVersion: "1.7.1-r0", VulnerabilityID: "CVE-2018-14056", Release: "1.0.0", Package: "znc", Repository: "community"},
	},
		advisories)
}

func TestBuildAdvisories(t *testing.T) {
	secFixes := map[string][]string{
		"2.6.8-r0": {"CVE-2019-10894"},
		"2.6.7-r1": {"CVE_2019-2426 XSA-201"}, // typo
		"2.6.5-r0": {"CVE_2019-5910 (+ some extra in parens)"},
	}

	assert.ElementsMatch(t, []alpine.Advisory{
		{IssueID: 0, VulnerabilityID: "CVE-2019-10894", Release: "1.0.0", Package: "testpkg", Repository: "testrepo", FixedVersion: "2.6.8-r0", Subject: "", Description: ""},
		{IssueID: 0, VulnerabilityID: "CVE-2019-2426", Release: "1.0.0", Package: "testpkg", Repository: "testrepo", FixedVersion: "2.6.7-r1", Subject: "", Description: ""},
		{IssueID: 0, VulnerabilityID: "XSA-201", Release: "1.0.0", Package: "testpkg", Repository: "testrepo", FixedVersion: "2.6.7-r1", Subject: "", Description: ""},
		{IssueID: 0, VulnerabilityID: "CVE-2019-5910", Release: "1.0.0", Package: "testpkg", Repository: "testrepo", FixedVersion: "2.6.5-r0", Subject: "", Description: ""}},
		alpine.BuildAdvisories(&alpine.Config{}, secFixes, "1.0.0", "testpkg", "testrepo"))
}

func TestConfig_Update(t *testing.T) {
	type cloneOrPull struct {
		returnArg map[string]struct{}
		err       error
	}
	type remoteBranch struct {
		returnArg []string
		err       error
	}

	testCases := []struct {
		name         string
		remoteBranch remoteBranch     // mock value
		cloneOrPull  cloneOrPull      // mock value
		checkout     map[string]error // mock value
		wantErr      error
	}{
		{
			name: "happy path",
			remoteBranch: remoteBranch{
				returnArg: []string{"origin/branch1-stable", "origin/branch2", "origin/branch3"},
			},
			checkout: map[string]error{mock.Anything: nil},
			wantErr:  nil,
		},
		{
			name:         "invalid branch name",
			remoteBranch: remoteBranch{returnArg: []string{"badbranch-stable"}},
			checkout:     map[string]error{mock.Anything: nil},
			wantErr:      nil,
		},
		{
			name: "git fails to show remote branches",
			remoteBranch: remoteBranch{
				returnArg: nil, err: errors.New("failed to show remote branch"),
			},
			checkout: map[string]error{mock.Anything: nil},
			wantErr:  xerrors.Errorf("failed to show branches: %w", errors.New("failed to show remote branch")),
		},
		{
			name: "git clone fails",
			cloneOrPull: cloneOrPull{
				returnArg: nil, err: errors.New("failed clone operation"),
			},
			checkout: map[string]error{mock.Anything: nil},
			wantErr:  xerrors.Errorf("failed to clone alpine repository: %w", errors.New("failed clone operation")),
		},
		{
			name: "git fails to checkout branch",
			remoteBranch: remoteBranch{
				returnArg: []string{"origin/branch1-stable", "origin/branch2", "origin/branch3"},
			},
			checkout: map[string]error{mock.Anything: errors.New("failed to checkout branch")},
			wantErr:  xerrors.Errorf("git failed to checkout branch: %w", errors.New("failed to checkout branch")),
		},
		{
			name: "git checkout of a particular branch fails",
			remoteBranch: remoteBranch{
				returnArg: []string{"origin/branch1-stable", "origin/branch2", "origin/branch3"},
			},
			checkout: map[string]error{
				"master":                errors.New("failed to checkout master"),
				"origin/branch1-stable": errors.New("failed to checkout branch1-stable"),
			},
			wantErr: xerrors.Errorf("git failed to checkout branch: %w", errors.New("failed to checkout branch1-stable")),
		},
	}

	cacheDir := "testdata"
	repoDir := filepath.Join(cacheDir, "aports")
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vulnListDir, err := ioutil.TempDir("", "TestUpdate")
			assert.NoError(t, err)
			defer os.RemoveAll(vulnListDir)

			mockGitConfig := new(MockGitConfig)

			// setup expectations with a placeholder in the argument list
			mockGitConfig.On("RemoteBranch", repoDir).Return(
				tc.remoteBranch.returnArg, tc.remoteBranch.err)
			mockGitConfig.On("CloneOrPull", mock.Anything, repoDir, "master").Return(
				tc.cloneOrPull.returnArg, tc.cloneOrPull.err)
			for arg, returnErr := range tc.checkout {
				mockGitConfig.On("Checkout", repoDir, arg).Return(returnErr)
			}

			ac := alpine.Config{
				GitClient:   mockGitConfig,
				CacheDir:    cacheDir,
				VulnListDir: vulnListDir,
			}
			fmt.Println(vulnListDir)

			err = ac.Update()
			if tc.wantErr != nil {
				assert.EqualError(t, err, tc.wantErr.Error())
			} else {
				assert.NoError(t, err)
				err = filepath.Walk(vulnListDir, func(path string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					}
					if info.IsDir() {
						return nil
					}
					paths := strings.Split(path, string(os.PathSeparator))
					assert.True(t, len(paths) > 3)

					golden := filepath.Join("testdata", "goldens",
						paths[len(paths)-3], paths[len(paths)-2], paths[len(paths)-1],
					)

					got, _ := ioutil.ReadFile(path)
					want, _ := ioutil.ReadFile(golden + ".golden")
					assert.Equal(t, string(want), string(got), "Alpine result json")
					return nil
				})
				assert.NoError(t, err)
			}
		})
	}
}
