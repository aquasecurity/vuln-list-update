package eoldates

type EOLData struct {
	Results []Result `json:"result"`
}

// Result matches the top-level objects in the endoflife.date API.
type Result struct {
	Name     string    `json:"name"`
	Releases []Release `json:"releases"`
}

// Release holds the version and EOL info for a single release.
type Release struct {
	Name    string `json:"name"`
	EOLFrom string `json:"eolFrom,omitempty"`
}
