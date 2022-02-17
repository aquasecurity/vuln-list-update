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

	"github.com/aquasecurity/vuln-list-update/chainguard"
	"github.com/aquasecurity/vuln-list-update/kevc"
	"github.com/aquasecurity/vuln-list-update/wolfi"

	githubql "github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/alma"
	"github.com/aquasecurity/vuln-list-update/alpine"
	alpineunfixed "github.com/aquasecurity/vuln-list-update/alpine-unfixed"
	"github.com/aquasecurity/vuln-list-update/amazon"
	arch_linux "github.com/aquasecurity/vuln-list-update/arch"
	"github.com/aquasecurity/vuln-list-update/cwe"
	"github.com/aquasecurity/vuln-list-update/debian/tracker"
	"github.com/aquasecurity/vuln-list-update/ghsa"
	"github.com/aquasecurity/vuln-list-update/git"
	"github.com/aquasecurity/vuln-list-update/glad"
	govulndb "github.com/aquasecurity/vuln-list-update/go-vulndb"
	"github.com/aquasecurity/vuln-list-update/mariner"
	"github.com/aquasecurity/vuln-list-update/nvd"
	oracleoval "github.com/aquasecurity/vuln-list-update/oracle/oval"
	"github.com/aquasecurity/vuln-list-update/osv"
	"github.com/aquasecurity/vuln-list-update/photon"
	redhatoval "github.com/aquasecurity/vuln-list-update/redhat/oval"
	"github.com/aquasecurity/vuln-list-update/redhat/securitydataapi"
	"github.com/aquasecurity/vuln-list-update/rocky"
	susecvrf "github.com/aquasecurity/vuln-list-update/suse/cvrf"
	"github.com/aquasecurity/vuln-list-update/ubuntu"
	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/aquasecurity/vuln-list-update/wrlinux"
)

const (
	repoURL          = "https://%s@github.com/%s/%s.git"
	defaultRepoOwner = "aquasecurity"
	defaultRepoName  = "vuln-list"
)

var (
	target = flag.String("target", "", "update target (nvd, alpine, alpine-unfixed, redhat, redhat-oval, "+
		"debian, debian-oval, ubuntu, amazon, oracle-oval, suse-cvrf, photon, arch-linux, ghsa, glad, cwe, osv, go-vulndb, mariner, kevc, wolfi, chainguard, wrlinux)")
	years        = flag.String("years", "", "update years (only redhat)")
	targetUri    = flag.String("target-uri", "", "alternative repository URI (only glad)")
	targetBranch = flag.String("target-branch", "", "alternative repository branch (only glad)")
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
	debug := os.Getenv("VULN_LIST_DEBUG") != ""

	repoOwner := utils.LookupEnv("VULNLIST_REPOSITORY_OWNER", defaultRepoOwner)
	repoName := utils.LookupEnv("VULNLIST_REPOSITORY_NAME", defaultRepoName)

	// Embed GitHub token to URL
	githubToken := os.Getenv("GITHUB_TOKEN")
	url := fmt.Sprintf(repoURL, githubToken, repoOwner, repoName)

	log.Printf("target repository is %s/%s\n", repoOwner, repoName)
	log.Printf("cloning/pulling into %s", utils.VulnListDir())

	if _, err := gc.CloneOrPull(url, utils.VulnListDir(), "main", debug); err != nil {
		return xerrors.Errorf("clone or pull error: %w", err)
	}

	defer func() {
		if debug {
			return
		}
		log.Println("git reset & clean")
		_ = gc.Clean(utils.VulnListDir())
	}()

	var commitMsg string
	switch *target {
	case "nvd":
		if err := nvd.Update(now.Year()); err != nil {
			return xerrors.Errorf("NVD update error: %w", err)
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
		if err := securitydataapi.Update(yearList); err != nil {
			return xerrors.Errorf("Red Hat Security Data API update error: %w", err)
		}
		commitMsg = "RedHat " + *years
	case "redhat-oval":
		rc := redhatoval.NewConfig()
		if err := rc.Update(); err != nil {
			return xerrors.Errorf("Red Hat OVALv2 update error: %w", err)
		}
		commitMsg = "Red Hat OVAL v2"
	case "debian":
		dc := tracker.NewClient()
		if err := dc.Update(); err != nil {
			return xerrors.Errorf("Debian update error: %w", err)
		}
		commitMsg = "Debian Security Bug Tracker"
	case "ubuntu":
		if err := ubuntu.Update(); err != nil {
			return xerrors.Errorf("Ubuntu update error: %w", err)
		}
		commitMsg = "Ubuntu CVE Tracker"
	case "alpine":
		au := alpine.NewUpdater()
		if err := au.Update(); err != nil {
			return xerrors.Errorf("Alpine update error: %w", err)
		}
		commitMsg = "Alpine Issue Tracker"
	case "alpine-unfixed":
		au := alpineunfixed.NewUpdater()
		if err := au.Update(); err != nil {
			return xerrors.Errorf("Alpine Secfixes Tracker update error: %w", err)
		}
		commitMsg = "Alpine Secfixes Tracker"
	case "amazon":
		ac := amazon.NewConfig()
		if err := ac.Update(); err != nil {
			return xerrors.Errorf("Amazon Linux update error: %w", err)
		}
		commitMsg = "Amazon Linux Security Center"
	case "oracle-oval":
		oc := oracleoval.NewConfig()
		if err := oc.Update(); err != nil {
			return xerrors.Errorf("Oracle OVAL update error: %w", err)
		}
		commitMsg = "Oracle Linux OVAL"
	case "suse-cvrf":
		sc := susecvrf.NewConfig()
		if err := sc.Update(); err != nil {
			return xerrors.Errorf("SUSE CVRF update error: %w", err)
		}
		commitMsg = "SUSE CVRF"
	case "photon":
		pc := photon.NewConfig()
		if err := pc.Update(); err != nil {
			return xerrors.Errorf("Photon update error: %w", err)
		}
		commitMsg = "Photon Security Advisories"
	case "ghsa":
		src := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: githubToken},
		)
		httpClient := oauth2.NewClient(context.Background(), src)

		gc := ghsa.NewConfig(githubql.NewClient(httpClient))
		if err := gc.Update(); err != nil {
			return xerrors.Errorf("GitHub Security Advisory update error: %w", err)
		}
		commitMsg = "GitHub Security Advisory"
	case "glad":
		gu := glad.NewUpdater(*targetUri, *targetBranch)
		if err := gu.Update(); err != nil {
			return xerrors.Errorf("GitLab Advisory Database update error: %w", err)
		}
		commitMsg = "GitLab Advisory Database"
	case "cwe":
		c := cwe.NewCWEConfig()
		if err := c.Update(); err != nil {
			return xerrors.Errorf("CWE update error: %w", err)
		}
		commitMsg = "CWE Advisories"
	case "arch-linux":
		al := arch_linux.NewArchLinux()
		if err := al.Update(); err != nil {
			return xerrors.Errorf("Arch Linux update error: %w", err)
		}
		commitMsg = "Arch Linux Security Tracker"
	case "alma":
		ac := alma.NewConfig()
		if err := ac.Update(); err != nil {
			return xerrors.Errorf("AlmaLinux update error: %w", err)
		}
		commitMsg = "AlmaLinux Security Advisory"
	case "rocky":
		rc := rocky.NewConfig()
		if err := rc.Update(); err != nil {
			return xerrors.Errorf("Rocky Linux update error: %w", err)
		}
		commitMsg = "Rocky Linux Security Advisory"
	case "osv":
		p := osv.NewOsv()
		if err := p.Update(); err != nil {
			return xerrors.Errorf("OSV update error: %w", err)
		}
		commitMsg = "OSV Database"
	case "go-vulndb":
		src := govulndb.NewVulnDB()
		if err := src.Update(); err != nil {
			return xerrors.Errorf("Go Vulnerability Database update error: %w", err)
		}
		commitMsg = "Go Vulnerability Database"
	case "mariner":
		src := mariner.NewConfig()
		if err := src.Update(); err != nil {
			return xerrors.Errorf("CBL-Mariner Vulnerability Data update error: %w", err)
		}
		commitMsg = "CBL-Mariner Vulnerability Data"
	case "kevc":
		src := kevc.NewConfig()
		if err := src.Update(); err != nil {
			return xerrors.Errorf("Known Exploited Vulnerability Catalog update error: %w", err)
		}
		commitMsg = "Known Exploited Vulnerability Catalog"
	case "wolfi":
		wu := wolfi.NewUpdater()
		if err := wu.Update(); err != nil {
			return xerrors.Errorf("Wolfi update error: %w", err)
		}
		commitMsg = "Wolfi Security Data"
	case "chainguard":
		cu := chainguard.NewUpdater()
		if err := cu.Update(); err != nil {
			return xerrors.Errorf("Chainguard update error: %w", err)
		}
		commitMsg = "Chainguard Security Data"
	case "wrlinux":
		if err := wrlinux.Update(); err != nil {
			return xerrors.Errorf("WRLinux update error: %w", err)
		}
		commitMsg = "Wind River CVE Tracker"
	default:
		return xerrors.New("unknown target")
	}

	if debug {
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
