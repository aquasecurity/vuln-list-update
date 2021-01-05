package alpine

import "encoding/json"

// secdb represents a type included in files from the Alpine repository
type secdb struct {
	Packages      json.RawMessage `json:"packages,omitempty"` // "packages" is an object or array
	Apkurl        string          `json:"apkurl,omitempty"`
	Archs         []string        `json:"archs,omitempty"`
	Urlprefix     string          `json:"urlprefix,omitempty"`
	Reponame      string          `json:"reponame,omitempty"`
	Distroversion string          `json:"distroversion,omitempty"`
}

type packages struct {
	Pkg pkg `json:"pkg"`
}

type pkg struct {
	Name     string                 `json:"name"`
	Secfixes map[string]interface{} `json:"secfixes"`
}

// advisory represents a type stored as a JSON file
type advisory struct {
	Name          string              `json:"name"`
	Secfixes      map[string][]string `json:"secfixes"`
	Apkurl        string              `json:"apkurl,omitempty"`
	Archs         []string            `json:"archs,omitempty"`
	Urlprefix     string              `json:"urlprefix,omitempty"`
	Reponame      string              `json:"reponame,omitempty"`
	Distroversion string              `json:"distroversion,omitempty"`
}
