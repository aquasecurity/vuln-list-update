package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/vuln-list-update/amazon"

	"github.com/aquasecurity/vuln-list-update/alpine"

	"github.com/aquasecurity/vuln-list-update/debian"
	"github.com/aquasecurity/vuln-list-update/git"
	"github.com/aquasecurity/vuln-list-update/nvd"
	debianoval "github.com/aquasecurity/vuln-list-update/oval/debian"
	"github.com/aquasecurity/vuln-list-update/redhat"
	"github.com/aquasecurity/vuln-list-update/ubuntu"
	"github.com/aquasecurity/vuln-list-update/utils"

	"golang.org/x/xerrors"
)

const (
	repoURL          = "https://%s@github.com/%s/%s.git"
	defaultRepoOwner = "aquasecurity"
	defaultRepoName  = "vuln-list"
)

var (
	target = flag.String("target", "", "update target (nvd, alpine, redhat, debian, ubuntu)")
	years  = flag.String("years", "", "update years (only redhat)")
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	flag.Parse()
	now := time.Now().UTC()
	gc := &git.Config{}
	vulnListDir := utils.VulnListDir()

	repoOwner := utils.LookupEnv("VULNLIST_REPOSITORY_OWNER", defaultRepoOwner)
	repoName := utils.LookupEnv("VULNLIST_REPOSITORY_NAME", defaultRepoName)

	// Embed GitHub token to URL
	githubToken := os.Getenv("GITHUB_TOKEN")
	url := fmt.Sprintf(repoURL, githubToken, repoOwner, repoName)

	log.Printf("target repository is %s/%s\n", repoOwner, repoName)

	if _, err := gc.CloneOrPull(url, utils.VulnListDir()); err != nil {
		return xerrors.Errorf("clone or pull error: %w", err)
	}

	var commitMsg string
	switch *target {
	case "nvd":
		if err := nvd.Update(now.Year()); err != nil {
			return xerrors.Errorf("error in NVD update: %w", err)
		}
		commitMsg = "NVD"
	case "redhat":
		var yearList []int
		for _, y := range strings.Split(*years, ",") {
			yearInt, err := strconv.Atoi(y)
			if err != nil {
				return xerrors.Errorf("invalid years: %w", err)
			}
			yearList = append(yearList, yearInt)
		}
		if len(yearList) == 0 {
			return xerrors.New("years must be specified")
		}
		if err := redhat.Update(yearList); err != nil {
			return err
		}
		commitMsg = "RedHat " + *years
	case "debian":
		if err := debian.Update(); err != nil {
			return xerrors.Errorf("error in Debian update: %w", err)
		}
		commitMsg = "Debian Security Bug Tracker"
	case "debian-oval":
		if err := debianoval.Update(); err != nil {
			return xerrors.Errorf("error in Debian OVAL update: %w", err)
		}
		commitMsg = "Debian OVAL"
	case "ubuntu":
		if err := ubuntu.Update(); err != nil {
			return xerrors.Errorf("error in Debian update: %w", err)
		}
		commitMsg = "Ubuntu CVE Tracker"
	case "alpine":
		ac := alpine.Config{
			GitClient:   gc,
			CacheDir:    utils.CacheDir(),
			VulnListDir: vulnListDir,
		}
		if err := ac.Update(); err != nil {
			return xerrors.Errorf("error in Alpine update: %w", err)
		}
		commitMsg = "Alpine Issue Tracker"
	case "amazon":
		ac := amazon.Config{
			LinuxMirrorListURI: amazon.LinuxMirrorListURI,
		}
		if err := ac.Update(); err != nil {
			return xerrors.Errorf("error in Amazon update: %w", err)
		}
		commitMsg = "Amazon Linux Security Center"
	default:
		return xerrors.New("unknown target")
	}

	if err := utils.SetLastUpdatedDate(*target, now); err != nil {
		return err
	}

	log.Println("git status")
	files, err := gc.Status(utils.VulnListDir())
	if err != nil {
		return xerrors.Errorf("failed to git status: %w", err)
	}

	// only last_updated.json
	if len(files) < 2 {
		log.Println("Skip commit and push")
		return nil
	}

	log.Println("git commit")
	if err = gc.Commit(utils.VulnListDir(), "./", commitMsg); err != nil {
		return xerrors.Errorf("failed to git commit: %w", err)
	}

	log.Println("git push")
	if err = gc.Push(utils.VulnListDir(), "master"); err != nil {
		return xerrors.Errorf("failed to git push: %w", err)
	}

	return nil
}
