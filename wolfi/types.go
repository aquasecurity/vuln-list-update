package wolfi

// secdb represents a type included in files from the Wolfi repository
type secdb struct {
	Packages      []packagesItem `json:"packages,omitempty"`
	Apkurl        string         `json:"apkurl,omitempty"`
	Archs         []string       `json:"archs,omitempty"`
	Urlprefix     string         `json:"urlprefix,omitempty"`
	Reponame      string         `json:"reponame,omitempty"`
	Distroversion string         `json:"distroversion,omitempty"`
}

type packagesItem struct {
	Pkg pkg `json:"pkg"`
}

type pkg struct {
	Name     string              `json:"name"`
	Secfixes map[string][]string `json:"secfixes"`
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
