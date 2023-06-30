package tracker

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/exp/slices"
)

var (
	// ref. https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/50ca55fb66ec7592f9bc1053a11dbf0bd50ee425/lib/python/sectracker/parsers.py#L185-186
	flagRegexp = `(?P<type>RESERVED|REJECTED)`

	// ref. https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/50ca55fb66ec7592f9bc1053a11dbf0bd50ee425/lib/python/sectracker/parsers.py#L187-188
	stringRegexp = `(?P<type>NOT-FOR-US|NOTE|TODO):\s+(?P<description>\S.*)`

	// e.g.
	// [stretch] - apache2 2.4.25-3+deb9u10
	// - libredwg <itp> (bug #595191)
	// ref. https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/50ca55fb66ec7592f9bc1053a11dbf0bd50ee425/lib/python/sectracker/parsers.py#L120-121
	pkgVersionRegexp = `(?:\[(?P<release>[a-z]+)\]\s)?-\s(?P<package>[A-Za-z0-9:.+-]+)\s*` +
		`(?:\s(?P<version>[A-Za-z0-9:.+~-]+)\s*)?(?:\s\((?P<inner>.*)\))?`

	// ref. https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/50ca55fb66ec7592f9bc1053a11dbf0bd50ee425/lib/python/sectracker/parsers.py#L142-143
	pkgPseudoRegexp = `(?:\[(?P<release>[a-z]+)\]\s)?-\s(?P<package>[A-Za-z0-9:.+-]+)` +
		`\s+<(?P<kind>[a-z-]+)>\s*(?:\s\((?P<inner>.*)\))?`

	// ref. https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/50ca55fb66ec7592f9bc1053a11dbf0bd50ee425/lib/python/sectracker/parsers.py#L175
	xrefRegexp = `\{(?P<xref>.*)\}`

	// inner annotations, like (bug #1345; low)
	// ref. https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/50ca55fb66ec7592f9bc1053a11dbf0bd50ee425/lib/python/sectracker/parsers.py#L85-99
	severityRegexp = regexp.MustCompile(`(unimportant|low|medium|high)`)
	bugNoRegexp    = regexp.MustCompile(`bug #(?P<bugno>\d+)`)

	// ref. https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/50ca55fb66ec7592f9bc1053a11dbf0bd50ee425/lib/python/sectracker/parsers.py#L140-141
	pseudoFreeText = []string{
		"no-dsa",
		"not-affected",
		"end-of-life",
		"ignored",
		"postponed",
	}
	pseudoStruct = []string{
		"unfixed",
		"removed",
		"itp",
		"undetermined",
	}
)

type Annotation struct {
	Original    string   `json:",omitempty"`
	Type        string   `json:",omitempty"`
	Release     string   `json:",omitempty"`
	Package     string   `json:",omitempty"`
	Kind        string   `json:",omitempty"`
	Version     string   `json:",omitempty"`
	Description string   `json:",omitempty"`
	Bugs        []string `json:",omitempty"`

	// inner annotations
	Severity string `json:",omitempty"`
	BugNo    int    `json:",omitempty"`
}

type annotationParser interface {
	Match(line string) []string
	Apply(match []string, ann *Annotation)
}

type annotationDispatcher struct {
	parsers []annotationParser
}

func newAnnotationDispatcher() annotationDispatcher {
	return annotationDispatcher{
		parsers: []annotationParser{
			newFlagAnnotation(),
			newStringAnnotation(),
			newPkgVersionAnnotation(),
			newPkgPseudoAnnotation(),
			newXrefAnnotation(),
		},
	}
}

func (d annotationDispatcher) parseAnnotation(line string) *Annotation {
	var once sync.Once
	var ann *Annotation

	for _, p := range d.parsers {
		match := p.Match(line)
		if len(match) != 0 {
			once.Do(func() {
				ann = &Annotation{
					Original: strings.TrimSpace(line),
				}
			})
			p.Apply(match, ann)
		}
	}
	return ann
}

func newAnnotationRegexp(s string) *regexp.Regexp {
	str := fmt.Sprintf("^\\s+%s\\s*$", s)
	return regexp.MustCompile(str)
}

// Parser for reserved/rejected vulnerabilities
type flagAnnotation struct {
	regex *regexp.Regexp
}

func newFlagAnnotation() flagAnnotation {
	return flagAnnotation{regex: newAnnotationRegexp(flagRegexp)}
}

func (a flagAnnotation) Match(line string) []string {
	return a.regex.FindStringSubmatch(line)
}

func (a flagAnnotation) Apply(match []string, ann *Annotation) {
	ann.Type = match[a.regex.SubexpIndex("type")]
}

// Parser for unaffected vulnerabilities
// e.g. NOT-FOR-US: Nightscout Web Monitor
// ref. https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/50ca55fb66ec7592f9bc1053a11dbf0bd50ee425/lib/python/sectracker/parsers.py#L187-188
type stringAnnotation struct {
	regex *regexp.Regexp
}

func newStringAnnotation() stringAnnotation {
	return stringAnnotation{regex: newAnnotationRegexp(stringRegexp)}
}

func (a stringAnnotation) Match(line string) []string {
	return a.regex.FindStringSubmatch(line)
}

func (a stringAnnotation) Apply(match []string, ann *Annotation) {
	ann.Type = match[a.regex.SubexpIndex("type")]
	ann.Description = match[a.regex.SubexpIndex("description")]
}

// Parser for fixed vulnerabilities
// e.g. [jessie] - suricata 2.0.7-2+deb8u4
// ref. https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/50ca55fb66ec7592f9bc1053a11dbf0bd50ee425/lib/python/sectracker/parsers.py#L120-138
type pkgVersionAnnotation struct {
	regex *regexp.Regexp
}

func newPkgVersionAnnotation() pkgVersionAnnotation {
	return pkgVersionAnnotation{regex: newAnnotationRegexp(pkgVersionRegexp)}
}

func (a pkgVersionAnnotation) Match(line string) []string {
	return a.regex.FindStringSubmatch(line)
}

func (a pkgVersionAnnotation) Apply(match []string, ann *Annotation) {
	release := match[a.regex.SubexpIndex("release")]
	pkg := match[a.regex.SubexpIndex("package")]
	version := match[a.regex.SubexpIndex("version")]
	inner := match[a.regex.SubexpIndex("inner")]
	severity, bugno := parseInner(inner)

	kind := "fixed"
	if version == "" {
		kind = "unfixed"
	}

	ann.Type = "package"
	ann.Release = release
	ann.Package = pkg
	ann.Kind = kind
	ann.Version = version
	ann.Severity = severity
	ann.BugNo = bugno
}

func parseInner(inner string) (string, int) {
	if inner == "" {
		return "", 0
	}

	var severity string
	var bugno int

	// e.g. (bug #1345; low)
	for _, ann := range strings.Split(inner, ";") {
		// Parse severity
		s := severityRegexp.FindString(ann)
		if s != "" {
			severity = s
			continue
		}

		// Parse bug number
		match := bugNoRegexp.FindStringSubmatch(ann)
		if len(match) > 0 {
			str := match[bugNoRegexp.SubexpIndex("bugno")]
			bugno, _ = strconv.Atoi(str)
		}
	}
	return severity, bugno
}

// Parser for unfixed vulnerabilities
// e.g. [bullseye] - putty <no-dsa> (Minor issue)
// ref. https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/50ca55fb66ec7592f9bc1053a11dbf0bd50ee425/lib/python/sectracker/parsers.py#L144
type pkgPseudoAnnotation struct {
	regex *regexp.Regexp
}

func newPkgPseudoAnnotation() pkgPseudoAnnotation {
	return pkgPseudoAnnotation{regex: newAnnotationRegexp(pkgPseudoRegexp)}
}

func (a pkgPseudoAnnotation) Match(line string) []string {
	return a.regex.FindStringSubmatch(line)
}

func (a pkgPseudoAnnotation) Apply(match []string, ann *Annotation) {
	release := match[a.regex.SubexpIndex("release")]
	pkg := match[a.regex.SubexpIndex("package")]
	kind := match[a.regex.SubexpIndex("kind")]
	inner := match[a.regex.SubexpIndex("inner")]

	ann.Type = "package"
	ann.Release = release
	ann.Package = pkg
	ann.Kind = kind

	if slices.Contains(pseudoFreeText, kind) {
		ann.Description = inner
	} else if slices.Contains(pseudoStruct, kind) {
		severity, bugno := parseInner(inner)
		ann.Severity = severity
		ann.BugNo = bugno
	}
}

// Parser for cross-reference
// e.g. {CVE-2021-29970 CVE-2021-29976 CVE-2021-30547}
// ref. https://salsa.debian.org/security-tracker-team/security-tracker/-/blob/50ca55fb66ec7592f9bc1053a11dbf0bd50ee425/lib/python/sectracker/parsers.py#L175-182
type xrefAnnotation struct {
	regex *regexp.Regexp
}

func newXrefAnnotation() xrefAnnotation {
	return xrefAnnotation{regex: newAnnotationRegexp(xrefRegexp)}
}

func (a xrefAnnotation) Match(line string) []string {
	return a.regex.FindStringSubmatch(line)
}

func (a xrefAnnotation) Apply(match []string, ann *Annotation) {
	xref := match[a.regex.SubexpIndex("xref")]
	ann.Type = "xref"
	ann.Bugs = strings.Fields(xref)
}
