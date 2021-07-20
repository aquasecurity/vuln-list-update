package tracker

import (
	"regexp"
)

var (
	dlaHeader = regexp.MustCompile(`^\[(\d\d) ([A-Z][a-z][a-z]) (\d{4})\] ` +
		`(?P<id>DLA-\d+(?:-\d+)?)\s+` +
		`(?P<description>.*?)\s*$`,
	)
)

type Header struct {
	Original    string `json:",omitempty"`
	Line        int    `json:",omitempty"`
	ID          string `json:",omitempty"`
	Description string `json:",omitempty"`
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
