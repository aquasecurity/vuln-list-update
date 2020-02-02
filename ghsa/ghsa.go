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

	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/cheggaaa/pb"
	githubql "github.com/shurcooL/githubql"
	"github.com/shurcooL/graphql"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"
)

// https://developer.github.com/v4/enum/securityadvisoryecosystem/
type SecurityAdvisoryEcosystem string

var (
	Composer SecurityAdvisoryEcosystem = "COMPOSER"
	Maven    SecurityAdvisoryEcosystem = "MAVEN"
	Npm      SecurityAdvisoryEcosystem = "NPM"
	Nuget    SecurityAdvisoryEcosystem = "NUGET"
	Pip      SecurityAdvisoryEcosystem = "PIP"
	Rubygems SecurityAdvisoryEcosystem = "RUBYGEMS"
)

const (
	ghsaDir = "ghsa"
	retry   = 5
)

var ecosystems = []SecurityAdvisoryEcosystem{Composer, Maven, Npm, Nuget, Pip, Rubygems}

type Config struct {
	VulnListDir string
	AppFs       afero.Fs
	Retry       int
	Client      GithubClient
}

type GithubClient interface {
	Query(ctx context.Context, q interface{}, variables map[string]interface{}) error
}

func NewConfig(client GithubClient) Config {
	return Config{
		VulnListDir: utils.VulnListDir(),
		AppFs:       afero.NewOsFs(),
		Retry:       retry,
		Client:      client,
	}
}

func (c Config) Update() error {
	log.Print("Fetching GithubSecurityAdvisory")

	for _, ecosystem := range ecosystems {
		err := c.update(ecosystem)
		if err != nil {
			return xerrors.Errorf("failed to update github security advisory: %w", err)
		}
	}
	return nil
}

func (c Config) update(ecosystem SecurityAdvisoryEcosystem) error {
	log.Printf("Fetching GithubSecurityAdvisory: %s", ecosystem)

	ghsas, err := c.FetchGithubSecurityAdvisories(ecosystem)
	if err != nil {
		return xerrors.Errorf("failed to fetch github security advisory: %w", err)
	}

	ghsaJsonMap := make(map[string]GithubSecurityAdvisoryJson)
	for _, ghsa := range ghsas {
		ghsa.Package.Name = strings.TrimSpace(ghsa.Package.Name)

		ghsaJson, ok := ghsaJsonMap[ghsa.Advisory.GhsaId+ghsa.Package.Name]
		if ok {
			va := VersionAdvisory{
				FirstPatchedVersion:    ghsa.FirstPatchedVersion,
				VulnerableVersionRange: ghsa.VulnerableVersionRange,
			}
			ghsaJson.VersionAdvisories = append(ghsaJson.VersionAdvisories, va)
			ghsaJsonMap[ghsa.Advisory.GhsaId+ghsa.Package.Name] = ghsaJson

		} else {
			ghsaJsonMap[ghsa.Advisory.GhsaId+ghsa.Package.Name] = GithubSecurityAdvisoryJson{
				Severity:  ghsa.Severity,
				UpdatedAt: ghsa.UpdatedAt,
				Package:   ghsa.Package,
				Advisory:  ghsa.Advisory,
				VersionAdvisories: []VersionAdvisory{
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
		dir := filepath.Join(c.VulnListDir, ghsaDir, strings.ToLower(string(ecosystem)), strings.Replace(ghsaJson.Package.Name, ":", "/", -1))
		err := c.saveGSA(dir, ghsaJson.Advisory.GhsaId, ghsaJson)
		if err != nil {
			return xerrors.Errorf("failed to save github security advisory: %w", err)
		}
		bar.Increment()
	}
	bar.Finish()
	return nil
}

func (c Config) FetchGithubSecurityAdvisories(ecosystem SecurityAdvisoryEcosystem) ([]GithubSecurityAdvisory, error) {
	var getVulnerabilitiesQuery GetVulnerabilitiesQuery
	var ghsas []GithubSecurityAdvisory
	variables := map[string]interface{}{
		"ecosystem": ecosystem,
		"total":     graphql.Int(100),
		"cursor":    (*githubql.String)(nil),
	}
	for {
		var err error
		for i := 0; i <= c.Retry; i++ {
			if i > 0 {
				wait := math.Pow(float64(i), 2) + float64(utils.RandInt()%10)
				log.Printf("retry after %f seconds\n", wait)
				time.Sleep(time.Duration(time.Duration(wait) * time.Second))
			}

			err = c.Client.Query(context.Background(), &getVulnerabilitiesQuery, variables)
			if err == nil {
				break
			}
		}
		if err != nil {
			return nil, xerrors.Errorf("failed to graphql api: %w", err)
		}

		ghsas = append(ghsas, getVulnerabilitiesQuery.Nodes...)
		if !getVulnerabilitiesQuery.PageInfo.HasNextPage {
			break
		}

		variables["cursor"] = githubql.NewString(getVulnerabilitiesQuery.PageInfo.EndCursor)
	}

	return ghsas, nil
}

func (c Config) saveGSA(dirName string, ghsaID, data interface{}) error {
	filePath := filepath.Join(dirName, fmt.Sprintf("%s.json", ghsaID))
	if err := c.AppFs.MkdirAll(dirName, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to create directory: %w", err)
	}

	fs := utils.NewFs(c.AppFs)
	if err := fs.WriteJSON(filePath, data); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}
