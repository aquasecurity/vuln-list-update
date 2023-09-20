package ghsa

import (
	"context"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cheggaaa/pb"
	githubql "github.com/shurcooL/githubv4"
	"github.com/shurcooL/graphql"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

// https://developer.github.com/v4/enum/securityadvisoryecosystem/
type SecurityAdvisoryEcosystem string

var (
	Composer   SecurityAdvisoryEcosystem = "COMPOSER"
	Maven      SecurityAdvisoryEcosystem = "MAVEN"
	Npm        SecurityAdvisoryEcosystem = "NPM"
	Nuget      SecurityAdvisoryEcosystem = "NUGET"
	Pip        SecurityAdvisoryEcosystem = "PIP"
	Rubygems   SecurityAdvisoryEcosystem = "RUBYGEMS"
	Go         SecurityAdvisoryEcosystem = "GO"
	Rust       SecurityAdvisoryEcosystem = "RUST"
	Erlang     SecurityAdvisoryEcosystem = "ERLANG"
	Pub        SecurityAdvisoryEcosystem = "PUB"
	Swift      SecurityAdvisoryEcosystem = "SWIFT"
	Ecosystems                           = []SecurityAdvisoryEcosystem{Composer, Maven, Npm, Nuget, Pip, Rubygems, Go, Erlang, Rust, Pub, Swift}

	wait = func(i int) time.Duration {
		sleep := math.Pow(float64(i), 2) + float64(utils.RandInt()%10)
		return time.Duration(sleep) * time.Second
	}
)

const (
	ghsaDir         = "ghsa"
	retry           = 5
	maxResponseSize = 100
)

type Config struct {
	vulnListDir string
	appFs       afero.Fs
	retry       int
	client      GithubClient
}

type GithubClient interface {
	Query(ctx context.Context, q interface{}, variables map[string]interface{}) error
}

func NewConfig(client GithubClient) Config {
	return Config{
		vulnListDir: utils.VulnListDir(),
		appFs:       afero.NewOsFs(),
		retry:       retry,
		client:      client,
	}
}

func (c Config) Update() error {
	log.Print("Fetching GitHub Security Advisory")

	for _, ecosystem := range Ecosystems {
		err := c.update(ecosystem)
		if err != nil {
			return xerrors.Errorf("failed to update github security advisory ,%s: %w", ecosystem, err)
		}
	}
	return nil
}

func (c Config) update(ecosystem SecurityAdvisoryEcosystem) error {
	log.Printf("Fetching GitHub Security Advisory: %s", ecosystem)

	dir := filepath.Join(c.vulnListDir, ghsaDir, strings.ToLower(string(ecosystem)))
	if err := os.RemoveAll(dir); err != nil {
		return xerrors.Errorf("unable to remove github security advisory directory: %w", err)
	}
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}

	ghsas, err := c.fetchGithubSecurityAdvisories(ecosystem)
	if err != nil {
		return xerrors.Errorf("failed to fetch github security advisory: %w", err)
	}

	ghsaJsonMap := make(map[string]GithubSecurityAdvisoryJson)
	for _, ghsa := range ghsas {
		// skip bad ghsa
		if ghsa.Package.Name == "" {
			continue
		}
		ghsa.Package.Name = strings.TrimSpace(ghsa.Package.Name)

		ghsaJson, ok := ghsaJsonMap[ghsa.Advisory.GhsaId+ghsa.Package.Name]
		if ok {
			va := Version{
				FirstPatchedVersion:    ghsa.FirstPatchedVersion,
				VulnerableVersionRange: ghsa.VulnerableVersionRange,
			}
			ghsaJson.Versions = append(ghsaJson.Versions, va)
			ghsaJsonMap[ghsa.Advisory.GhsaId+ghsa.Package.Name] = ghsaJson

		} else {
			ghsaJsonMap[ghsa.Advisory.GhsaId+ghsa.Package.Name] = GithubSecurityAdvisoryJson{
				Severity:  ghsa.Severity,
				UpdatedAt: ghsa.UpdatedAt,
				Package:   ghsa.Package,
				Advisory:  ghsa.Advisory,
				Versions: []Version{
					{
						FirstPatchedVersion:    ghsa.FirstPatchedVersion,
						VulnerableVersionRange: ghsa.VulnerableVersionRange,
					},
				},
			}
		}
	}

	bar := pb.StartNew(len(ghsaJsonMap))
	for _, ghsaJson := range ghsaJsonMap {
		pkgName := strings.Replace(ghsaJson.Package.Name, ":", "/", -1)
		// Part Swift advisories have `https://` prefix or `.git` suffix
		// e.g. https://github.com/github/advisory-database/blob/76f65b0d0fdac39c8b0e834ab03562b5f80d5b27/advisories/github-reviewed/2023/06/GHSA-r6ww-5963-7r95/GHSA-r6ww-5963-7r95.json#L21
		// https://github.com/github/advisory-database/blob/76f65b0d0fdac39c8b0e834ab03562b5f80d5b27/advisories/github-reviewed/2023/07/GHSA-jq43-q8mx-r7mq/GHSA-jq43-q8mx-r7mq.json#L21
		// Trim them to get correct directory
		if ecosystem == Swift {
			pkgName = strings.TrimPrefix(pkgName, "https///")
			pkgName = strings.TrimSuffix(pkgName, ".git")
		}
		dir := filepath.Join(c.vulnListDir, ghsaDir, strings.ToLower(string(ecosystem)), pkgName)
		err := c.saveGSHA(dir, ghsaJson.Advisory.GhsaId, ghsaJson)
		if err != nil {
			return xerrors.Errorf("failed to save github security advisory: %w", err)
		}
		bar.Increment()
	}
	bar.Finish()
	return nil
}

func (c Config) fetchGithubSecurityAdvisories(ecosystem SecurityAdvisoryEcosystem) ([]GithubSecurityAdvisory, error) {
	var getVulnerabilitiesQuery GetVulnerabilitiesQuery
	var ghsas []GithubSecurityAdvisory
	variables := map[string]interface{}{
		"ecosystem": ecosystem,
		"total":     graphql.Int(maxResponseSize),
		"cursor":    (*githubql.String)(nil),
	}
	for {
		var err error
		for i := 0; i <= c.retry; i++ {
			if i > 0 {
				sleep := wait(i)
				log.Printf("retry after %s", sleep)
				time.Sleep(sleep)
			}

			err = c.client.Query(context.Background(), &getVulnerabilitiesQuery, variables)
			if err == nil || len(getVulnerabilitiesQuery.Nodes) > 0 {
				break
			}
		}
		// GitHub GraphQL API may return error and one of nodes == nil
		// We must write other nodes.
		// Bad node will be skipped in 'update' function
		if err != nil && len(getVulnerabilitiesQuery.Nodes) == 0 {
			return nil, xerrors.Errorf("graphql api error: %w", err)
		}

		ghsas = append(ghsas, getVulnerabilitiesQuery.Nodes...)
		if !getVulnerabilitiesQuery.PageInfo.HasNextPage {
			break
		}

		variables["cursor"] = githubql.NewString(getVulnerabilitiesQuery.PageInfo.EndCursor)
	}
	return ghsas, nil
}

func (c Config) saveGSHA(dirName string, ghsaID string, data interface{}) error {
	fileName := fmt.Sprintf("%s.json", ghsaID)
	if err := utils.WriteJSON(c.appFs, dirName, fileName, data); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}
