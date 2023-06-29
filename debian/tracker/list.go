package tracker

import (
	"regexp"
)

var (
	dlaHeader = regexp.MustCompile(`^\[(\d\d) ([A-Z][a-z][a-z]) (\d{4})\] ` +
		`(?P<id>DLA-\d+(?:-\d+)?)\s+` +
		`(?P<description>.*?)\s*$`,
	)
	dsaHeader = regexp.MustCompile(`^\[(\d\d) ([A-Z][a-z][a-z]) (\d{4})\] ` +
		`(?P<id>DSA-\d+(?:-\d+)?)\s+` +
		`(?P<description>.*?)\s*$`,
	)
	cveHeader = regexp.MustCompile(`^(?P<id>(?:CVE-\d{4}-(?:\d{4,}|XXXX)|TEMP-\d+-\S+))\s*(?P<description>.*?)\s*$`)
)

type Header struct {
	Original    string `json:",omitempty"`
	ID          string `json:",omitempty"`
	Description string `json:",omitempty"`
}

type cveList struct{}

func (l cveList) ParseHeader(line string) *Header {
	results := cveHeader.FindStringSubmatch(line)
	if len(results) == 0 {
		return nil
	}

	id := results[cveHeader.SubexpIndex("id")]
	description := results[cveHeader.SubexpIndex("description")]

	return &Header{
		Original:    line,
		ID:          id,
		Description: description,
	}
}

func (l cveList) Dir() string {
	return "CVE"
}

type dlaList struct{}

func (l dlaList) ParseHeader(line string) *Header {
	results := dlaHeader.FindStringSubmatch(line)
	if len(results) == 0 {
		return nil
	}

	id := results[dlaHeader.SubexpIndex("id")]
	description := results[dlaHeader.SubexpIndex("description")]

	return &Header{
		Original:    line,
		ID:          id,
		Description: description,
	}
}

func (l dlaList) Dir() string {
	return "DLA"
}

type dsaList struct{}

func (l dsaList) ParseHeader(line string) *Header {
	results := dsaHeader.FindStringSubmatch(line)
	if len(results) == 0 {
		return nil
	}

	id := results[dsaHeader.SubexpIndex("id")]
	description := results[dsaHeader.SubexpIndex("description")]

	return &Header{
		Original:    line,
		ID:          id,
		Description: description,
	}
}

func (l dsaList) Dir() string {
	return "DSA"
}
