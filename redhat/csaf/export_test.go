package csaf

import (
	"time"
)

// ParseCSVForTest exports parseCSV for testing.
func ParseCSVForTest(b []byte, since time.Time) ([]csvEntry, error) {
	return parseCSV(b, since)
}

// ParseArchiveDateForTest exports parseArchiveDate for testing.
func ParseArchiveDateForTest(archiveName string) (time.Time, error) {
	return parseArchiveDate(archiveName)
}
