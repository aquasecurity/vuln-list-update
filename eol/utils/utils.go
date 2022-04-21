package utils

import (
	"encoding/json"
	"log"
	"time"

	"github.com/aquasecurity/vuln-list-update/utils"
	"golang.org/x/xerrors"
)

//Cycles schema: https://endoflife.date/docs/api
type Cycles []struct {
	Cycle   string      `json:"cycle"`
	Lts     bool        `json:"lts"`
	Support interface{} `json:"support"` // Support value can be string or bool
	Eol     interface{} `json:"eol"`     // Eol value can be string or bool
}

// GetLifeCycles return []Cycles from github.com/endoflife-date/endoflife.date
func GetLifeCycles(distName, url string, retry int) (Cycles, error) {
	log.Printf("Fetching %s end-of-life dates...", distName)
	b, err := utils.FetchURL(url, "", retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to get list of end-of-life dates from url: %w", err)
	}

	var cycles Cycles
	err = json.Unmarshal(b, &cycles)
	if err != nil {
		return nil, err
	}

	return cycles, nil
}

func MoveToEndOfDay(d time.Time) time.Time {
	// Move time to end of day
	return d.Add(time.Hour*23 + time.Minute*59 + time.Second*59)
}
