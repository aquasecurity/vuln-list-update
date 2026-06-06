package alinux

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parseEVR(t *testing.T) {
	tests := []struct {
		name        string
		evr         string
		wantEpoch   string
		wantVersion string
		wantRelease string
	}{
		{
			name:        "version-release without epoch",
			evr:         "7.61.1-22.al8.3",
			wantEpoch:   "0",
			wantVersion: "7.61.1",
			wantRelease: "22.al8.3",
		},
		{
			name:        "with epoch",
			evr:         "1:1.0.2k-25.al2",
			wantEpoch:   "1",
			wantVersion: "1.0.2k",
			wantRelease: "25.al2",
		},
		{
			name:        "kernel version",
			evr:         "5.10.134-16.3.al8",
			wantEpoch:   "0",
			wantVersion: "5.10.134",
			wantRelease: "16.3.al8",
		},
		{
			name:        "explicit epoch 0",
			evr:         "0:2.14.5-1.59.al7",
			wantEpoch:   "0",
			wantVersion: "2.14.5",
			wantRelease: "1.59.al7",
		},
		{
			name:        "version only no release",
			evr:         "1.0.0",
			wantEpoch:   "0",
			wantVersion: "1.0.0",
			wantRelease: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			epoch, version, release := parseEVR(tt.evr)
			assert.Equal(t, tt.wantEpoch, epoch)
			assert.Equal(t, tt.wantVersion, version)
			assert.Equal(t, tt.wantRelease, release)
		})
	}
}
