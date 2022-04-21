package eol

import (
	"github.com/aquasecurity/vuln-list-update/eol/alma"
	"github.com/aquasecurity/vuln-list-update/eol/alpine"
	"github.com/aquasecurity/vuln-list-update/eol/centos"
	"github.com/aquasecurity/vuln-list-update/eol/debian"
	"github.com/aquasecurity/vuln-list-update/eol/opensuse"
	"github.com/aquasecurity/vuln-list-update/eol/redhat"
	"github.com/aquasecurity/vuln-list-update/eol/rocky"
)

var all = []EolSrc{
	alma.NewConfig(),
	alpine.NewConfig(),
	centos.NewConfig(),
	debian.NewConfig(),
	opensuse.NewConfig(),
	redhat.NewConfig(),
	rocky.NewConfig(),
}
