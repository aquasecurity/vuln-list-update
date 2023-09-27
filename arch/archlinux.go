package arch

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	archLinuxDir       = "arch-linux"
	securityTrackerURL = "https://security.archlinux.org/json"
	retry              = 3
)

type securityGroups []struct {
	Name       string   `json:"name"`
	Packages   []string `json:"packages"`
	Status     string   `json:"status"`
	Severity   string   `json:"severity"`
	Type       string   `json:"type"`
	Affected   string   `json:"affected"`
	Fixed      string   `json:"fixed"`
	Issues     []string `json:"issues"`
	Advisories []string `json:"advisories"`
}

type options struct {
	url   string
	dir   string
	retry int
}

type option func(*options)

func WithURL(url string) option {
	return func(opts *options) { opts.url = url }
}

func WithDir(dir string) option {
	return func(opts *options) { opts.dir = dir }
}

func WithRetry(retry int) option {
	return func(opts *options) { opts.retry = retry }
}

type ArchLinux struct {
	*options
}

func NewArchLinux(opts ...option) ArchLinux {
	o := &options{
		url:   securityTrackerURL,
		dir:   filepath.Join(utils.VulnListDir(), archLinuxDir),
		retry: retry,
	}

	for _, opt := range opts {
		opt(o)
	}

	return ArchLinux{
		options: o,
	}
}

func (al ArchLinux) Update() error {
	log.Println("Fetching Arch Linux data...")
	asgs, err := al.retrieveSecurityGroups()
	if err != nil {
		return xerrors.Errorf("failed to retrieve Arch Linux Security Groups: %w", err)
	}

	log.Printf("Removing old dir (%s)...", al.dir)
	if err = os.RemoveAll(al.dir); err != nil {
		return xerrors.Errorf("failed to remove Arch Linux dir: %w", err)
	}

	// Save all JSON files
	log.Println("Saving new data...")
	bar := pb.StartNew(len(asgs))
	if err = os.MkdirAll(al.dir, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to create the directory: %w", err)
	}
	for _, asg := range asgs {
		filePath := filepath.Join(al.dir, fmt.Sprintf("%s.json", asg.Name))
		if err = utils.Write(filePath, asg); err != nil {
			return xerrors.Errorf("failed to write Arch Linux CVE details: %w", err)
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}

func (al ArchLinux) retrieveSecurityGroups() (securityGroups, error) {
	secJSON, err := utils.FetchURL(al.url, "", al.retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch cve data from Arch Linux. err: %w", err)
	}

	var asgs securityGroups
	if err = json.Unmarshal(secJSON, &asgs); err != nil {
		return nil, xerrors.Errorf("json unmarshal error: %w", err)
	}
	return asgs, nil
}
