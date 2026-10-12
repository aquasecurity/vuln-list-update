package tracker

import (
	"testing"
	"time"
)

// SetTrackerRetryWait overrides the wait between Security Tracker download retries for the duration of the test.
func SetTrackerRetryWait(t *testing.T, d time.Duration) {
	old := trackerRetryWait
	trackerRetryWait = d
	t.Cleanup(func() { trackerRetryWait = old })
}
