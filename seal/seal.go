package seal

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/osv"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	securityTrackerURL = "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip"
	sealDir            = "seal"
)

var ecosystemToManager = map[string]string{
	"alpine":       "alpine",
	"debian":       "debian",
	"ubuntu":       "debian",
	"redhat":       "rpm",
	"centos":       "rpm",
	"Oracle Linux": "rpm",
	"cbl-mariner":  "rpm",
}

type sealDatabase struct {
	Type string `json:"type"`
}

type options struct {
	url string
	dir string
}

type option func(*options)

type Database struct {
	*options
}

func WithURL(url string) option {
	return func(opts *options) {
		opts.url = url
	}
}

func WithDir(dir string) option {
	return func(opts *options) {
		opts.dir = dir
	}
}

func NewSeal(opts ...option) Database {
	o := &options{
		url: securityTrackerURL,
		dir: filepath.Join(utils.VulnListDir(), sealDir),
	}
	for _, opt := range opts {
		opt(o)
	}
	return Database{
		options: o,
	}
}

func getEcosystem(affected osv.Affected) string {
	if affected.Database == nil {
		ecosystem := strings.SplitN(affected.Package.Ecosystem, ":", 2)[0]
		ecosystem = strings.ToLower(ecosystem)
		return ecosystemToManager[ecosystem]
	}

	bytes, _ := json.Marshal(affected.Database)
	var db *sealDatabase
	json.Unmarshal(bytes, &db)
	return strings.ToLower(db.Type)
}

func (seal *Database) handleSingleFile(path string, d fs.DirEntry, err error) error {
	if d.IsDir() || err != nil {
		return err
	}

	f, err := os.Open(path)
	if err != nil {
		return xerrors.Errorf("file open error (%s): %w", path, err)
	}

	var parsed osv.OSV
	if err = json.NewDecoder(f).Decode(&parsed); err != nil {
		return xerrors.Errorf("unable to parse json %s: %w", path, err)
	}

	published, _ := time.Parse(time.DateOnly, parsed.Published)
	parsed.Published = published.Format(time.RFC3339)
	affected := parsed.Affected[0]
	ecosystem := getEcosystem(affected)
	filePath := filepath.Join(seal.dir, ecosystem, affected.Package.Name, fmt.Sprintf("%s.json", parsed.ID))
	if err = utils.Write(filePath, parsed); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}

func (seal *Database) Update() error {
	ctx := context.Background()

	log.Printf("Updating Seal Security advisory")
	tempDir, err := utils.DownloadToTempDir(ctx, seal.url)
	if err != nil {
		return xerrors.Errorf("failed to download %s: %w", seal.url, err)
	}

	err = filepath.WalkDir(tempDir, seal.handleSingleFile)
	if err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}

	return nil
}
