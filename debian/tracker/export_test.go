package tracker

import (
	"testing"
	"time"
)

// SetTrackerRetryWait overrides the wait between Security Tracker download retries for the duration of the test.
func SetTrackerRetryWait(t *testing.T, d time.Duration) {
	t.Helper()
	old := trackerRetryWait
	trackerRetryWait = d
	t.Cleanup(func() { trackerRetryWait = old })
}

// SetCloneOrPull overrides the Security Tracker git fetch implementation for the duration of the test.
func SetCloneOrPull(t *testing.T, f func(url, dir string) error) {
	t.Helper()
	old := cloneOrPull
	cloneOrPull = f
	t.Cleanup(func() { cloneOrPull = old })
}
