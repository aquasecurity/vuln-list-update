package cvrfcve

type Cvrf struct {
	Title           string           `xml:"DocumentTitle"`
	Tracking        DocumentTracking `xml:"DocumentTracking"`
	Vulnerabilities []Vulnerability  `xml:"Vulnerability"`
}

type DocumentTracking struct {
	ID                 string `xml:"Identification>ID"`
	InitialReleaseDate string `xml:"InitialReleaseDate" json:",omitempty"`
	CurrentReleaseDate string `xml:"CurrentReleaseDate" json:",omitempty"`
}

type Vulnerability struct {
	CVE           string        `xml:"CVE"`
	Threats       []Threat      `xml:"Threats>Threat" json:",omitempty"`
	References    []Reference   `xml:"References>Reference" json:",omitempty"`
	CVSSScoreSets CVSSScoreSets `xml:"CVSSScoreSets" json:",omitempty"`
}

type Threat struct {
	Type     string `xml:"Type,attr"`
	Severity string `xml:"Description"`
}

type Reference struct {
	URL         string `xml:"URL"`
	Description string `xml:"Description"`
}

type CVSSScoreSets struct {
	ScoreSetV2 []ScoreSetV2 `xml:"ScoreSetV2" json:",omitempty"`
	ScoreSetV3 []ScoreSetV3 `xml:"ScoreSetV3" json:",omitempty"`
}

type ScoreSetV2 struct {
	BaseScoreV2 string `xml:"BaseScoreV2" json:",omitempty"`
	VectorV2    string `xml:"VectorV2" json:",omitempty"`
}

type ScoreSetV3 struct {
	BaseScoreV3 string `xml:"BaseScoreV3" json:",omitempty"`
	VectorV3    string `xml:"VectorV3" json:",omitempty"`
}
