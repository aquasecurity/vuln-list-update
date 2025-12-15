package csaf_test

import (
	"archive/tar"
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/txtar"

	csaf "github.com/aquasecurity/vuln-list-update/redhat/csaf"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const archiveName = "csaf_vex_2025-12-06.tar.zst"

func TestConfig_Update(t *testing.T) {
	tests := []struct {
		name         string
		txtarFile    string
		changesCSV   string
		deletionsCSV string
		existingData bool
		wantFiles    []string
		wantErr      string
	}{
		{
			name:      "first run - archive only",
			txtarFile: "testdata/happy.txtar",
			// No changes after archive date
			changesCSV:   "",
			deletionsCSV: "",
			wantFiles: []string{
				"2024/cve-2024-0208.json",
			},
		},
		{
			name:    "404",
			wantErr: "failed to fetch VEX archive: failed to fetch URL",
		},
		{
			name:      "invalid csaf",
			txtarFile: "testdata/invalid.txtar",
			wantErr:   "'category' is missing",
		},
		{
			name:         "delta update - changes only",
			txtarFile:    "testdata/happy.txtar",
			existingData: true,
			// Entry after archive date (2025-12-06)
			changesCSV:   `"2024/cve-2024-0208.json","2025-12-10T10:00:00+00:00"`,
			deletionsCSV: "",
			wantFiles: []string{
				"2024/cve-2024-0208.json",
			},
		},
		{
			name:         "delta update - deletions only",
			txtarFile:    "testdata/happy.txtar",
			existingData: true,
			changesCSV:   "",
			// Delete the file that exists
			deletionsCSV: `"2024/cve-2024-0208.json","2025-12-10T10:00:00+00:00"`,
			wantFiles:    []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse txtar file
			var ar *txtar.Archive
			if tt.txtarFile != "" {
				ar = parseTxtar(t, tt.txtarFile)
			}

			tmpDir := t.TempDir()
			createTestArchive(t, ar, tmpDir)

			// Setup test server
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "archive_latest.txt"):
					w.Write([]byte(archiveName))
				case strings.HasSuffix(r.URL.Path, ".tar.zst"):
					http.ServeFile(w, r, filepath.Join(tmpDir, archiveName))
				case strings.HasSuffix(r.URL.Path, "changes.csv"):
					w.Write([]byte(tt.changesCSV))
				case strings.HasSuffix(r.URL.Path, "deletions.csv"):
					w.Write([]byte(tt.deletionsCSV))
				case strings.HasSuffix(r.URL.Path, ".json"):
					// Serve individual CVE files from txtar
					if ar != nil {
						for _, f := range ar.Files {
							if strings.HasSuffix(r.URL.Path, filepath.Base(f.Name)) {
								w.Write(f.Data)
								return
							}
						}
					}
					w.WriteHeader(http.StatusNotFound)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer ts.Close()

			// Set up VulnListDir for last_updated.json
			vulnListDir := t.TempDir()
			utils.SetVulnListDir(vulnListDir)
			baseDir := filepath.Join(vulnListDir, "csaf-vex")

			// If existingData is true, populate baseDir from txtar and set last_updated
			if tt.existingData {
				populateTestData(t, ar, baseDir)
				// Set last_updated to a time before the CSV entries (2025-12-10)
				// so that delta update will process them
				err := utils.SetLastUpdatedDate("csaf-vex", time.Date(2025, 12, 5, 0, 0, 0, 0, time.UTC))
				require.NoError(t, err)
			}

			c := csaf.NewConfig(
				csaf.WithBaseDir(baseDir),
				csaf.WithBaseURL(lo.Must(url.Parse(ts.URL))),
				csaf.WithRetry(0),
			)

			err := c.Update()
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err, tt.name)

			var fileCount int
			err = filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
				require.NoError(t, err)
				if info.IsDir() {
					return nil
				}
				fileCount++

				relPath, err := filepath.Rel(baseDir, path)
				require.NoError(t, err)
				require.True(t, slices.Contains(tt.wantFiles, relPath), relPath)
				return nil
			})
			assert.NoError(t, err, tt.name)
			assert.Equal(t, len(tt.wantFiles), fileCount, tt.name)
		})
	}
}

func TestParseCSV(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		since   time.Time
		want    int
		wantErr string
	}{
		{
			name: "valid entries - filter by date",
			input: `"2025/cve-2025-7195.json","2025-12-12T10:07:18+00:00"
"2024/cve-2024-0001.json","2025-12-11T09:00:00+00:00"
"2024/cve-2024-0002.json","2025-12-09T08:00:00+00:00"`,
			since: time.Date(2025, 12, 10, 0, 0, 0, 0, time.UTC),
			want:  2, // Only first two entries are after since
		},
		{
			name:  "empty file",
			input: "",
			since: time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
			want:  0,
		},
		{
			name:    "invalid timestamp",
			input:   `"2025/cve-2025-7195.json","invalid-date"`,
			since:   time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
			wantErr: "failed to parse timestamp",
		},
		{
			name:    "wrong number of fields",
			input:   `"only-one-field"`,
			since:   time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
			wantErr: "invalid CSV record",
		},
		{
			name: "early termination - stops at old entry",
			input: `"2025/cve-2025-0001.json","2025-12-12T10:00:00+00:00"
"2025/cve-2025-0002.json","2025-12-05T10:00:00+00:00"
"2025/cve-2025-0003.json","2025-12-12T11:00:00+00:00"`,
			since: time.Date(2025, 12, 6, 0, 0, 0, 0, time.UTC),
			want:  1, // Stops at second entry (before since), doesn't read third
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := csaf.ParseCSVForTest([]byte(tt.input), tt.since)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Len(t, entries, tt.want)
		})
	}
}

func TestParseArchiveDate(t *testing.T) {
	tests := []struct {
		name        string
		archiveName string
		wantDate    time.Time
		wantErr     string
	}{
		{
			name:        "valid archive name",
			archiveName: "csaf_vex_2025-12-06.tar.zst",
			wantDate:    time.Date(2025, 12, 6, 0, 0, 0, 0, time.UTC),
		},
		{
			name:        "invalid format",
			archiveName: "csaf_vex.tar.zst",
			wantErr:     "failed to parse archive date",
		},
		{
			name:        "invalid date",
			archiveName: "csaf_vex_2025-13-45.tar.zst",
			wantErr:     "failed to parse date",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := csaf.ParseArchiveDateForTest(tt.archiveName)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantDate, got)
		})
	}
}

func parseTxtar(t *testing.T, path string) *txtar.Archive {
	t.Helper()
	ar, err := txtar.ParseFile(path)
	require.NoError(t, err)
	return ar
}

func createTestArchive(t *testing.T, ar *txtar.Archive, tmpDir string) {
	t.Helper()
	if ar == nil {
		return
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Add files from txtar archive to tar
	fsys, err := txtar.FS(ar)
	require.NoError(t, err)
	err = tw.AddFS(fsys)
	require.NoError(t, err)
	require.NoError(t, tw.Close())

	var compressedBuf bytes.Buffer
	enc, err := zstd.NewWriter(&compressedBuf)
	require.NoError(t, err)

	_, err = enc.Write(buf.Bytes())
	require.NoError(t, err)
	require.NoError(t, enc.Close())

	err = os.WriteFile(filepath.Join(tmpDir, archiveName), compressedBuf.Bytes(), 0644)
	require.NoError(t, err)
}

// populateTestData copies txtar files to baseDir using os.CopyFS.
func populateTestData(t *testing.T, ar *txtar.Archive, baseDir string) {
	t.Helper()
	if ar == nil {
		return
	}
	fsys, err := txtar.FS(ar)
	require.NoError(t, err)
	err = os.CopyFS(baseDir, fsys)
	require.NoError(t, err)
}
