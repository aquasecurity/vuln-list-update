package alpine

var (
	ShouldOverwrite = (*Config).shouldOverwrite
	ParsePkgVerRel  = (*Config).parsePkgVerRel
	ParseSecFixes   = (*Config).parseSecFixes
	WalkApkBuild    = (*Config).walkApkBuild
	BuildAdvisories = (*Config).buildAdvisories
)
