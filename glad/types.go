package glad

type advisory struct {
	Identifier       string   `yaml:"identifier"`
	Identifiers      []string `yaml:"identifiers" json:"identifiers,omitempty"`
	PackageSlug      string   `yaml:"package_slug"`
	Title            string   `yaml:"title"`
	Description      string   `yaml:"description"`
	Date             string   `yaml:"date"`
	Pubdate          string   `yaml:"pubdate"`
	AffectedRange    string   `yaml:"affected_range"`
	FixedVersions    []string `yaml:"fixed_versions"`
	AffectedVersions string   `yaml:"affected_versions"`
	NotImpacted      string   `yaml:"not_impacted"`
	Solution         string   `yaml:"solution"`
	Urls             []string `yaml:"urls"`
	CvssV2           string   `yaml:"cvss_v2"`
	CvssV3           string   `yaml:"cvss_v3"`
	UUID             string   `yaml:"uuid"`
}
