package eol

import (
	"github.com/aquasecurity/vuln-list-update/eol/alma"
	"github.com/aquasecurity/vuln-list-update/eol/alpine"
	"github.com/aquasecurity/vuln-list-update/eol/amazon"
	"github.com/aquasecurity/vuln-list-update/eol/centos"
	"github.com/aquasecurity/vuln-list-update/eol/debian"
	"github.com/aquasecurity/vuln-list-update/eol/opensuse"
	"github.com/aquasecurity/vuln-list-update/eol/redhat"
	"github.com/aquasecurity/vuln-list-update/eol/rocky"
	"github.com/aquasecurity/vuln-list-update/eol/sles"
	"github.com/aquasecurity/vuln-list-update/eol/ubuntu"
)

var all = []EolSrc{
	alma.NewConfig(),
	alpine.NewConfig(),
	amazon.NewConfig(),
	centos.NewConfig(),
	debian.NewConfig(),
	opensuse.NewConfig(),
	redhat.NewConfig(),
	rocky.NewConfig(),
	sles.NewConfig(),
	ubuntu.NewConfig(),
}
