/*
 * Copyright (c) 2022 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify, or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

package wrlinux

import (
	"bufio"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquasecurity/vuln-list-update/git"
	"github.com/aquasecurity/vuln-list-update/utils"
	"github.com/araddon/dateparse"
	"golang.org/x/xerrors"
)

const (
	cveTrackerDir = "windriver-cve-tracker"
	windriverDir  = "wrlinux"
)

var (
	repoURLs = []string{
		"https://distro.windriver.com/git/windriver-cve-tracker.git",
	}
	targets = []string{
		"active",
	}
	statuses = []string{
		"released",
		"pending",
		"not-affected",
		"ignored",
	}
)

type Vulnerability struct {
	Candidate   string
	PublicDate  time.Time
	Description string
	References  []string
	Notes       []string
	Priority    string
	Bugs        []string
	Patches     map[Package]Statuses
}

type Package string

type Release string

type Statuses map[Release]Status

type Status struct {
	Status string
	Note   string
}

func Update() error {
	var err error
	gc := git.Config{}
	dir := filepath.Join(utils.CacheDir(), cveTrackerDir)
	for _, url := range repoURLs {
		_, err = gc.CloneOrPull(url, dir, "master", false)
		if err == nil {
			break
		}
	}
	if err != nil {
		return xerrors.Errorf("failed to clone or pull: %w", err)
	}
	defer os.RemoveAll(dir)

	dst := filepath.Join(utils.VulnListDir(), windriverDir)
	log.Printf("removing windriver directory %s", dst)
	if err := os.RemoveAll(dst); err != nil {
		return xerrors.Errorf("failed to remove windriver directory: %w", err)
	}

	log.Println("walking windriver-cve-tracker ...")
	for _, target := range targets {
		if err := walkDir(filepath.Join(dir, target)); err != nil {
			return err
		}
	}

	return nil
}

func walkDir(root string) error {
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return xerrors.Errorf("file walk error: %w", err)
		}
		if info.IsDir() {
			return nil
		}

		base := filepath.Base(path)
		if !strings.HasPrefix(base, "CVE-") {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return xerrors.Errorf("error in file open: %w", err)
		}
		vuln, err := parse(f)
		if err != nil {
			return xerrors.Errorf("error in parse: %w", err)
		}

		if err = utils.SaveCVEPerYear(filepath.Join(utils.VulnListDir(), windriverDir), vuln.Candidate, vuln); err != nil {
			return xerrors.Errorf("error in save: %w", err)
		}

		return nil
	})

	if err != nil {
		return xerrors.Errorf("error in walk: %w", err)
	}
	return nil
}

func parse(r io.Reader) (vuln *Vulnerability, err error) {
	vuln = &Vulnerability{}
	vuln.Patches = map[Package]Statuses{}

	var lines []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		// Skip
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// Parse Candidate
		if strings.HasPrefix(line, "Candidate:") {
			line = strings.TrimPrefix(line, "Candidate:")
			vuln.Candidate = strings.TrimSpace(line)
			continue
		}

		// Parse PublicDate
		if strings.HasPrefix(line, "PublicDate:") {
			line = strings.TrimPrefix(line, "PublicDate:")
			line = strings.TrimSpace(line)
			vuln.PublicDate, _ = dateparse.ParseAny(line)
			continue
		}

		// Parse Description
		if strings.HasPrefix(line, "Description:") {
			var description []string
			for strings.HasPrefix(lines[i+1], " ") {
				i++
				line = strings.TrimSpace(lines[i])
				description = append(description, line)
			}
			vuln.Description = strings.Join(description, " ")
			continue
		}

		// Parse References
		if strings.HasPrefix(line, "References:") {
			for strings.HasPrefix(lines[i+1], " ") {
				i++
				line = strings.TrimSpace(lines[i])
				vuln.References = append(vuln.References, line)
			}
			continue
		}

		// Parse Notes
		if strings.HasPrefix(line, "Notes:") {
			for strings.HasPrefix(lines[i+1], " ") {
				i++
				line = strings.TrimSpace(lines[i])
				note := []string{line}
				for strings.HasPrefix(lines[i+1], "  ") {
					i++
					l := strings.TrimSpace(lines[i])
					note = append(note, l)
				}
				vuln.Notes = append(vuln.Notes, strings.Join(note, " "))
			}
			continue
		}

		// Parse Priority
		if strings.HasPrefix(line, "Priority:") {
			line = strings.TrimPrefix(line, "Priority:")
			vuln.Priority = strings.TrimSpace(line)
			continue
		}

		// Parse Bugs
		if strings.HasPrefix(line, "Bugs:") {
			for strings.HasPrefix(lines[i+1], " ") {
				i++
				line = strings.TrimSpace(lines[i])
				vuln.Bugs = append(vuln.Bugs, line)
			}
			continue
		}

		// Parse Patches, this indicates if a CVE has been fixed, if so, in which release.
		// eg: 10.21.20.1_vim: released (10.21.20.14)
		//     <affected_release>_<package_name>: <status>
		// where status: <pending/ignored/released/not-affected> [(note)]
		// release: 10.21.20.1
		// package: vim
		// status: released
		// note: 10.21.20.14 (fixed release)
		s := strings.SplitN(line, ":", 2)
		if len(s) < 2 {
			continue
		}

		status := strings.TrimSpace(s[1])
		if isPatch(status) && !strings.HasPrefix(s[0], "Patches_") {
			pkgRel := strings.SplitN(s[0], "_", 2)
			release := Release(pkgRel[0])
			pkgName := Package(pkgRel[1])

			fields := strings.Fields(status)
			status := Status{
				Status: fields[0],
			}
			// status is any of: pending/ignored/released/not-affected
			//                   followed by optional note in ()
			// if the status contains multiple fields,
			// it also has the release in which it was fixed.
			// ie, released (10.21.20.14)
			if len(fields) > 1 {
				note := strings.Join(fields[1:], " ")
				status.Note = strings.Trim(note, "()")
			}

			if existingStatuses, ok := vuln.Patches[pkgName]; ok {
				existingStatuses[release] = status
				vuln.Patches[pkgName] = existingStatuses
			} else {
				statuses := Statuses{}
				statuses[release] = status
				vuln.Patches[pkgName] = statuses
			}
		}
	}
	return vuln, nil
}

func isPatch(s string) bool {
	for _, status := range statuses {
		if strings.HasPrefix(s, status) {
			return true
		}
	}
	return false
}
