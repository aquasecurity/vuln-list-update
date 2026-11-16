package ubuntu

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"strings"

	"golang.org/x/xerrors"
)

const (
	archiveURL = "https://archive.ubuntu.com/ubuntu"
	// oldReleasesURL keeps the releases that have been removed from archive.ubuntu.com
	oldReleasesURL = "https://old-releases.ubuntu.com/ubuntu"
)

var (
	archivePockets    = []string{"", "-updates", "-security"}
	archiveComponents = []string{"main", "restricted", "universe", "multiverse"}
)

// addArchiveBinaries adds binary packages from the Binary field of Sources.gz indices
// to the source packages that have OSV records in the release.
func (u OSVUpdater) addArchiveBinaries(ctx context.Context, data osvData) error {
	wanted := make(map[string]map[string]*sourceBinaries) // release => source package => binaries
	for key, sb := range data.sources {
		if wanted[key.release] == nil {
			wanted[key.release] = make(map[string]*sourceBinaries)
		}
		wanted[key.release][key.source] = sb
	}

	releases := make([]string, 0, len(wanted))
	for release := range wanted {
		releases = append(releases, release)
	}
	slices.Sort(releases)

	for _, release := range releases {
		codename, ok := data.codenames[release]
		if !ok {
			log.Printf("[Ubuntu OSV] No codename for %s, skipping the Ubuntu archive", release)
			continue
		}
		baseURL, err := u.archiveBaseURL(ctx, codename)
		if err != nil {
			return xerrors.Errorf("failed to find %s in the Ubuntu archive: %w", codename, err)
		}

		log.Printf("[Ubuntu OSV] Reading Sources.gz of %s (%s) from %s", release, codename, baseURL)
		sources := wanted[release]
		for _, pocket := range archivePockets {
			for _, component := range archiveComponents {
				indexURL := fmt.Sprintf("%s/dists/%s%s/%s/source/Sources.gz", baseURL, codename, pocket, component)
				err = readSourcesIndex(ctx, indexURL, func(source string, binaries []string) {
					sb, ok := sources[source]
					if !ok {
						return
					}
					for _, name := range binaries {
						sb.binaries[name] = struct{}{}
					}
				})
				if err != nil {
					return xerrors.Errorf("failed to read %s: %w", indexURL, err)
				}
			}
		}
	}
	return nil
}

// archiveBaseURL returns the archive that has the release.
func (u OSVUpdater) archiveBaseURL(ctx context.Context, codename string) (string, error) {
	for _, baseURL := range []string{u.archiveURL, u.oldReleasesURL} {
		releaseURL := fmt.Sprintf("%s/dists/%s/Release", baseURL, codename)
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, releaseURL, nil)
		if err != nil {
			return "", xerrors.Errorf("failed to build a request: %w", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", xerrors.Errorf("request error: %w", err)
		}
		resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			return baseURL, nil
		case http.StatusNotFound:
			continue
		default:
			return "", xerrors.Errorf("bad response code from %s: %d", releaseURL, resp.StatusCode)
		}
	}
	return "", xerrors.Errorf("%s is not found in %s and %s", codename, u.archiveURL, u.oldReleasesURL)
}

func readSourcesIndex(ctx context.Context, indexURL string, fn func(source string, binaries []string)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, indexURL, nil)
	if err != nil {
		return xerrors.Errorf("failed to build a request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return xerrors.Errorf("request error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return xerrors.Errorf("bad response code: %d", resp.StatusCode)
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return xerrors.Errorf("failed to open gzip: %w", err)
	}
	defer gr.Close()

	return parseSourcesIndex(gr, fn)
}

// parseSourcesIndex calls fn with the Package and Binary fields of each paragraph of a Sources index.
// A field value may continue on the following lines that start with a space or a tab.
func parseSourcesIndex(r io.Reader, fn func(source string, binaries []string)) error {
	var source, binary, field string
	flush := func() {
		if source != "" && binary != "" {
			var binaries []string
			for name := range strings.SplitSeq(binary, ",") {
				if name = strings.TrimSpace(name); name != "" {
					binaries = append(binaries, name)
				}
			}
			fn(source, binaries)
		}
		source, binary, field = "", "", ""
	}

	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return xerrors.Errorf("read error: %w", err)
		}
		eof := err != nil
		line = strings.TrimRight(line, "\r\n")

		switch {
		case line == "":
			flush()
		case line[0] == ' ' || line[0] == '\t':
			if field == "Binary" {
				binary += " " + line
			}
		default:
			name, value, _ := strings.Cut(line, ":")
			field = name
			switch name {
			case "Package":
				source = strings.TrimSpace(value)
			case "Binary":
				binary = value
			}
		}

		if eof {
			flush()
			return nil
		}
	}
}
