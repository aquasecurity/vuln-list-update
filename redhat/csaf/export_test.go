package csaf

import (
	"io"
	"time"
)

// ParseCSVStreamForTest exports parseCSVStream for testing.
func ParseCSVStreamForTest(r io.Reader, since time.Time) ([]csvEntry, error) {
	return parseCSVStream(r, since)
}

// ParseArchiveDateForTest exports parseArchiveDate for testing.
func ParseArchiveDateForTest(archiveName string) (time.Time, error) {
	return parseArchiveDate(archiveName)
}
