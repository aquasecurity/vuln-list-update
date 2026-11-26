package csaf

import (
	"github.com/gocsaf/csaf/v3/csaf"
)

// SplitAdvisory exposes splitAdvisory for testing, returning the files' contents keyed by their names.
func (c *Config) SplitAdvisory(advisory *csaf.Advisory) (map[string]string, error) {
	files, err := c.splitAdvisory(advisory)
	if err != nil {
		return nil, err
	}
	got := make(map[string]string, len(files))
	for _, f := range files {
		got[f.path] = string(f.data)
	}
	return got, nil
}

// SplitVulnerability exposes splitVulnerability for testing, returning the files' contents keyed by their names.
func (c *Config) SplitVulnerability(prefix string, v *csaf.Vulnerability) (map[string]string, *csaf.Vulnerability, error) {
	rest, files, err := c.splitVulnerability(prefix, v)
	if err != nil {
		return nil, nil, err
	}
	got := make(map[string]string, len(files))
	for _, f := range files {
		got[f.path] = string(f.data)
	}
	return got, rest, nil
}
