package alpine

type secdb struct {
	Packages      interface{} `json:"packages,omitempty"`
	Apkurl        string      `json:"apkurl,omitempty"`
	Archs         []string    `json:"archs,omitempty"`
	Urlprefix     string      `json:"urlprefix,omitempty"`
	Reponame      string      `json:"reponame,omitempty"`
	Distroversion string      `json:"distroversion,omitempty"`
}
