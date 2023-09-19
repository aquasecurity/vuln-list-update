package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ExtractVersions(t *testing.T) {
	tests := []struct {
		name             string
		version          string
		less             string
		wantIntroduce    string
		wantLastAffected string
	}{
		{name: "range less with minor", version: "1.2", less: "1.2.5", wantIntroduce: "1.2.0", wantLastAffected: "1.2.5"},
		{name: "range less", version: "", less: "1.2.5", wantIntroduce: "1.2.0", wantLastAffected: "1.2.5"},
		{name: "range lessThen", version: "", less: "1.2.5", wantIntroduce: "1.2.0", wantLastAffected: "1.2.5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIntoduce, gotLastAffected := UpdateVersions(tt.less, tt.version)
			assert.Equal(t, gotIntoduce, tt.wantIntroduce)
			assert.Equal(t, gotLastAffected, tt.wantLastAffected)
		})
	}
}

func Test_ExtractRangeVersions(t *testing.T) {
	tests := []struct {
		name             string
		version          string
		wantIntroduce    string
		wantLastAffected string
	}{
		{name: "range versions", version: "1.2.3 - 1.2.5", wantIntroduce: "1.2.3", wantLastAffected: "1.2.5"},
		{name: "single versions", version: "1.2.5", wantIntroduce: "1.2.5", wantLastAffected: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIntoduce, gotLastAffected := ExtractRangeVersions(tt.version)
			assert.Equal(t, gotIntoduce, tt.wantIntroduce)
			assert.Equal(t, gotLastAffected, tt.wantLastAffected)
		})
	}
}
