package rapidfort

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/git"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	rapidfortDir  = "rapidfort"
	defaultRepoURL = "https://github.com/rapidfort/security-advisories.git"
	repoBranch    = "main"
	repoCloneDir  = "rapidfort-advisories" // subdir inside cacheDir
	repoOSPath    = "OS"                   // OS/{osName}/{package}.json inside the repo
)

// defaultSupportedOSes lists the OS subdirectories to ingest from the cloned repo.
var defaultSupportedOSes = []string{"ubuntu", "alpine", "redhat"}

type option func(c *Updater)

func WithVulnListDir(v string) option {
	return func(c *Updater) { c.vulnListDir = v }
}

func WithCacheDir(v string) option {
	return func(c *Updater) { c.cacheDir = v }
}

// WithRepoDir bypasses git clone and reads advisory files from this directory directly.
// Useful in tests or when the repo is already available locally.
func WithRepoDir(v string) option {
	return func(c *Updater) { c.repoDir = v }
}

// WithRepoURL overrides the git clone URL (e.g. to use SSH or inject a token).
func WithRepoURL(v string) option {
	return func(c *Updater) { c.repoURL = v }
}

// WithSupportedOSes overrides the list of OS directories to process (used in tests).
func WithSupportedOSes(oses []string) option {
	return func(c *Updater) { c.supportedOSes = oses }
}

// Updater clones the RapidFort security-advisories repo and writes per-version
// per-package JSON files to vuln-list/rapidfort/{os}/{version}/{package}.json.
type Updater struct {
	vulnListDir   string
	cacheDir      string
	repoDir       string // if set, skip git clone and read from here
	repoURL       string
	supportedOSes []string
}

func NewUpdater(options ...option) *Updater {
	repoURL := buildRepoURL()
	updater := &Updater{
		vulnListDir:   utils.VulnListDir(),
		cacheDir:      utils.CacheDir(),
		repoURL:       repoURL,
		supportedOSes: defaultSupportedOSes,
	}
	for _, opt := range options {
		opt(updater)
	}
	return updater
}

// buildRepoURL returns the clone URL, injecting GITHUB_TOKEN if available
// so private repos work in CI without SSH key setup.
func buildRepoURL() string {
	token := os.Getenv("GITHUB_TOKEN")
	if token != "" {
		return fmt.Sprintf("https://%s@github.com/rapidfort/security-advisories.git", token)
	}
	return defaultRepoURL
}

// Update clones (or pulls) the advisories repo, then processes all supported OSes.
func (u *Updater) Update() error {
	repoDir := u.repoDir
	if repoDir == "" {
		// Clone or pull into the cache directory.
		repoDir = filepath.Join(u.cacheDir, repoCloneDir)
		log.Printf("Updating RapidFort advisories repo in %s", repoDir)
		gc := git.Config{}
		if _, err := gc.CloneOrPull(u.repoURL, repoDir, repoBranch, false); err != nil {
			return xerrors.Errorf("failed to clone/pull RapidFort advisory repo: %w", err)
		}
	}

	outDir := filepath.Join(u.vulnListDir, rapidfortDir)
	if err := os.RemoveAll(outDir); err != nil {
		return xerrors.Errorf("failed to remove old RapidFort directory: %w", err)
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return xerrors.Errorf("failed to create RapidFort output directory: %w", err)
	}

	for _, osName := range u.supportedOSes {
		srcDir := filepath.Join(repoDir, repoOSPath, osName)
		if ok, _ := utils.Exists(srcDir); !ok {
			// Keep as warning: signals missing OS dir without spamming counts.
			log.Printf("warn: RapidFort advisories directory not found, skipping: %s", srcDir)
			continue
		}

		log.Printf("Processing RapidFort advisories for %s...", osName)
		if err := u.processOS(outDir, osName, srcDir); err != nil {
			return xerrors.Errorf("failed to process %s advisories: %w", osName, err)
		}
	}
	return nil
}

// processOS walks all *.json files in srcDir, parses each SourcePackageAdvisory,
// and writes split per-version output files under outDir/{osName}/.
func (u *Updater) processOS(outDir, osName, srcDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return xerrors.Errorf("failed to read %s: %w", srcDir, err)
	}

	var (
		totalSourceFiles    int
		totalOutputFiles    int
		readErrorFiles      int
		invalidJSONFiles    int
		missingPkgNameFiles int
	)

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		totalSourceFiles++

		filePath := filepath.Join(srcDir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			// Keep per-file warning: actionable and explains *which* file failed.
			log.Printf("warn: failed to read %s: %v", filePath, err)
			readErrorFiles++
			continue
		}

		var src SourcePackageAdvisory
		if err := json.Unmarshal(data, &src); err != nil {
			log.Printf("warn: failed to parse %s: %v", filePath, err)
			invalidJSONFiles++
			continue
		}

		if src.PackageName == "" {
			log.Printf("warn: missing package_name in %s, skipping", filePath)
			missingPkgNameFiles++
			continue
		}

		written, err := u.saveAdvisory(outDir, osName, src)
		if err != nil {
			return xerrors.Errorf("failed to save advisory for %s/%s: %w", osName, src.PackageName, err)
		}
		totalOutputFiles += written
	}

	failures := readErrorFiles + invalidJSONFiles + missingPkgNameFiles
	if failures == 0 {
		log.Printf("Finished RapidFort advisories for %s (source=%d, output=%d).", osName, totalSourceFiles, totalOutputFiles)
		return nil
	}

	// Print counts with failure breakdown.
	log.Printf(
		"Finished RapidFort advisories for %s with issues: %d read errors, %d invalid JSON, %d missing package_name (source=%d, output=%d)",
		osName,
		readErrorFiles, invalidJSONFiles, missingPkgNameFiles,
		totalSourceFiles, totalOutputFiles,
	)

	return nil
}

// saveAdvisory splits a SourcePackageAdvisory by version and writes one file per version,
// returning the number of files written.
// Output path: {outDir}/{osName}/{version}/{packageName}.json
func (u *Updater) saveAdvisory(outDir, osName string, src SourcePackageAdvisory) (int, error) {
	written := 0
	for version, cveMap := range src.Advisory {
		if len(cveMap) == 0 {
			continue
		}
		pkg := PackageAdvisory{
			PackageName:   src.PackageName,
			DistroVersion: version,
			Advisories:    cveMap,
		}
		filePath := filepath.Join(outDir, osName, version, fmt.Sprintf("%s.json", src.PackageName))
		if err := utils.Write(filePath, pkg); err != nil {
			return written, xerrors.Errorf("failed to write %s: %w", filePath, err)
		}
		written++
	}
	return written, nil
}
