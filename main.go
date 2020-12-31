package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/vuln-list-update/cwe"

	githubql "github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/alpine"
	"github.com/aquasecurity/vuln-list-update/amazon"
	susecvrf "github.com/aquasecurity/vuln-list-update/cvrf/suse"
	"github.com/aquasecurity/vuln-list-update/debian"
	"github.com/aquasecurity/vuln-list-update/ghsa"
	"github.com/aquasecurity/vuln-list-update/git"
	"github.com/aquasecurity/vuln-list-update/nvd"
	debianoval "github.com/aquasecurity/vuln-list-update/oval/debian"
	oracleoval "github.com/aquasecurity/vuln-list-update/oval/oracle"
	redhatoval "github.com/aquasecurity/vuln-list-update/oval/redhat"
	"github.com/aquasecurity/vuln-list-update/photon"
	"github.com/aquasecurity/vuln-list-update/redhat"
	"github.com/aquasecurity/vuln-list-update/ubuntu"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	repoURL          = "https://%s@github.com/%s/%s.git"
	defaultRepoOwner = "aquasecurity"
	defaultRepoName  = "vuln-list"
)

var (
	target = flag.String("target", "", "update target (nvd, alpine, redhat, redhat-oval, debian, debian-oval, ubuntu, amazon, oracle-oval, suse-cvrf, photon, ghsa, cwe)")
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

	if _, err := gc.CloneOrPull(url, utils.VulnListDir(), "main"); err != nil {
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
	case "redhat-oval":
		rc := redhatoval.NewConfig()
		if err := rc.Update(); err != nil {
			return xerrors.Errorf("error in Red Hat OVAL v2 update: %w", err)
		}
		commitMsg = "Red Hat OVAL v2"
	case "debian":
		dc := debian.NewClient()
		if err := dc.Update(); err != nil {
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
			VulnListDir:        utils.VulnListDir(),
		}
		if err := ac.Update(); err != nil {
			return xerrors.Errorf("error in Amazon update: %w", err)
		}
		commitMsg = "Amazon Linux Security Center"
	case "oracle-oval":
		oc := oracleoval.NewConfig()
		if err := oc.Update(); err != nil {
			return xerrors.Errorf("error in Oracle Linux OVAL update: %w", err)
		}
		commitMsg = "Oracle Linux OVAL"
	case "suse-cvrf":
		sc := susecvrf.NewConfig()
		if err := sc.Update(); err != nil {
			return xerrors.Errorf("error in SUSE CVRF update: %w", err)
		}
		commitMsg = "SUSE CVRF"
	case "photon":
		pc := photon.NewConfig()
		if err := pc.Update(); err != nil {
			return xerrors.Errorf("error in Photon update: %w", err)
		}
		commitMsg = "Photon Security Advisories"
	case "ghsa":
		src := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: githubToken},
		)
		httpClient := oauth2.NewClient(context.Background(), src)

		gc := ghsa.NewConfig(githubql.NewClient(httpClient))
		if err := gc.Update(); err != nil {
			return xerrors.Errorf("error in GitHub Security Advisory update: %w", err)
		}
		commitMsg = "GitHub Security Advisory"
	case "cwe":
		c := cwe.NewCWEConfig()
		if err := c.Update(); err != nil {
			return xerrors.Errorf("error in CWE update: %w", err)
		}
		commitMsg = "CWE Advisories"
	default:
		return xerrors.New("unknown target")
	}

	if os.Getenv("VULN_LIST_DEBUG") != "" {
		return nil
	}

	if err := utils.SetLastUpdatedDate(*target, now); err != nil {
		return err
	}

	log.Println("git status")
	files, err := gc.Status(utils.VulnListDir())
	if err != nil {
		return xerrors.Errorf("git status error: %w", err)
	}

	// only last_updated.json
	if len(files) < 2 {
		log.Println("Skip commit and push")
		return nil
	}

	log.Println("git commit")
	if err = gc.Commit(utils.VulnListDir(), "./", commitMsg); err != nil {
		return xerrors.Errorf("git commit error: %w", err)
	}

	log.Println("git push")
	if err = gc.Push(utils.VulnListDir(), "main"); err != nil {
		return xerrors.Errorf("git push error: %w", err)
	}

	return nil
}
