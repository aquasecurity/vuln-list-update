package k8s

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizedVersion(t *testing.T) {
	tests := []struct {
		Name    string
		Version *MitreVersion
		Want    *MitreVersion
	}{
		{Name: "validate n/a version ", Version: &MitreVersion{Version: "n/a"}, Want: &MitreVersion{Version: "n/a"}},
		{Name: "validate unspecified version ", Version: &MitreVersion{Version: "unspecified"}, Want: &MitreVersion{Version: "unspecified"}},
		{Name: "validate less equal sign and version", Version: &MitreVersion{LessThanOrEqual: "<=", Version: "1.3.4"}, Want: &MitreVersion{Version: "1.3.4", LessThanOrEqual: "1.3.4"}},
		{Name: "validate less sign in version", Version: &MitreVersion{Version: "< 1.3.4"}, Want: &MitreVersion{Version: "< 1.3.4", LessThan: "1.3.4"}},
		{Name: "validate prior to then sign in version", Version: &MitreVersion{Version: "prior to 1.3.4"}, Want: &MitreVersion{Version: "prior to 1.3.4", LessThan: "1.3.4"}},
		{Name: "validate prior to with minor in version", Version: &MitreVersion{Version: "prior to 1.3"}, Want: &MitreVersion{Version: "1.3.0", LessThan: "1.3.0"}},
		{Name: "validate less  with astrix", Version: &MitreVersion{LessThan: "1.3*"}, Want: &MitreVersion{Version: "1.3"}},
		{Name: "validate less  with x", Version: &MitreVersion{Version: "1.3.x"}, Want: &MitreVersion{Version: "1.3"}},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			got, _ := sanitizedVersions(tt.Version)
			assert.Equal(t, got, tt.Want)

		})
	}
}

func TestMergedVersion(t *testing.T) {
	tests := []struct {
		Name                 string
		affectedVersions     []*Version
		WantAffectedVersions []*Version
	}{
		{Name: "merge regular version", affectedVersions: []*Version{
			{Introduced: "1.2"},
			{Introduced: "1.3"},
			{Introduced: "1.4.1", LastAffected: "1.4.6"},
		}, WantAffectedVersions: []*Version{
			{Introduced: "1.2.0", LastAffected: "1.4.6"}},
		},
		{Name: "merge mixed version", affectedVersions: []*Version{
			{Introduced: "1.3"},
			{Introduced: "1.4"},
			{Introduced: "1.5"},
			{Introduced: "1.6"},
			{Introduced: "1.7.0", Fixed: "1.7.14"},
			{Introduced: "1.8.0", Fixed: "1.8.9"},
		}, WantAffectedVersions: []*Version{
			{Introduced: "1.3.0", Fixed: "1.7.14"},
			{Introduced: "1.8.0", Fixed: "1.8.9"}},
		},
		{Name: "merge all minor version", affectedVersions: []*Version{
			{Introduced: "1.3"},
			{Introduced: "1.4"},
			{Introduced: "1.5"},
			{Introduced: "1.6"},
			{Introduced: "1.7"},
		}, WantAffectedVersions: []*Version{
			{Introduced: "1.3.0", Fixed: "1.8.0"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			gotLastAffected, err := mergeVersionRange(tt.affectedVersions)
			assert.NoError(t, err)
			assert.Equal(t, gotLastAffected, tt.WantAffectedVersions)

		})
	}
}
