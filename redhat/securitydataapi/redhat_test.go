package securitydataapi

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCalculateFetchTimeout(t *testing.T) {
	tests := []struct {
		name     string
		cveCount int
		expected time.Duration
	}{
		{
			name:     "zero CVEs falls back to minFetchTimeout",
			cveCount: 0,
			expected: 30 * time.Minute,
		},
		{
			name:     "small year falls back to minFetchTimeout",
			cveCount: 6000, // 6000 * 250ms = 1500s = 25m < 30m
			expected: 30 * time.Minute,
		},
		{
			name:     "medium year scales above minimum",
			cveCount: 8000, // 8000 * 250ms = 2000s = 33m20s
			expected: 2000 * time.Second,
		},
		{
			name:     "large year scales proportionally",
			cveCount: 20000, // 20000 * 250ms = 5000s = 83m20s
			expected: 5000 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := calculateFetchTimeout(tt.cveCount)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
