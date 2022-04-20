package eol

import (
	"github.com/aquasecurity/vuln-list-update/eol/alma"
	"github.com/aquasecurity/vuln-list-update/eol/alpine"
	"github.com/aquasecurity/vuln-list-update/eol/debian"
	"github.com/aquasecurity/vuln-list-update/eol/rocky"
)

var all = []EolSrc{
	alma.NewConfig(),
	alpine.NewConfig(),
	rocky.NewConfig(),
	debian.NewConfig(),
}
