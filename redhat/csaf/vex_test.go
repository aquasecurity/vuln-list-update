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

	csaf "github.com/aquasecurity/vuln-list-update/redhat/csaf"
	"github.com/aquasecurity/vuln-list-update/utils"
)

const archiveName = "csaf_vex_2025-12-06.tar.zst"

func TestConfig_Update(t *testing.T) {
	tests := []struct {
		name         string
		dir          string
		changesCSV   string
		deletionsCSV string
		existingData bool
		wantFiles    []string
		wantErr      string
	}{
		{
			name: "first run - archive only",
			dir:  "testdata/happy",
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
			name:    "invalid csaf",
			dir:     "testdata/invalid",
			wantErr: "'category' is missing",
		},
		{
			name:         "delta update - changes only",
			dir:          "testdata/happy",
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
			dir:          "testdata/happy",
			existingData: true,
			changesCSV:   "",
			// Delete the file that exists
			deletionsCSV: `"2024/cve-2024-0208.json","2025-12-10T10:00:00+00:00"`,
			wantFiles:    []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			createTestArchive(t, tt.dir, tmpDir)

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
					// Serve individual CVE files from testdata
					http.ServeFile(w, r, filepath.Join("testdata/happy", filepath.Base(r.URL.Path)))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer ts.Close()

			// Set up VulnListDir for last_updated.json
			vulnListDir := t.TempDir()
			utils.SetVulnListDir(vulnListDir)
			baseDir := filepath.Join(vulnListDir, "csaf-vex")

			// If existingData is true, create the baseDir and set last_updated
			if tt.existingData {
				// Create the baseDir with initial data from archive
				createTestArchive(t, tt.dir, tmpDir)
				c := csaf.NewConfig(
					csaf.WithBaseDir(baseDir),
					csaf.WithBaseURL(lo.Must(url.Parse(ts.URL))),
					csaf.WithRetry(0),
				)
				// First run to populate data
				emptyChangesServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch {
					case strings.HasSuffix(r.URL.Path, "archive_latest.txt"):
						w.Write([]byte(archiveName))
					case strings.HasSuffix(r.URL.Path, ".tar.zst"):
						http.ServeFile(w, r, filepath.Join(tmpDir, archiveName))
					case strings.HasSuffix(r.URL.Path, "changes.csv"):
						w.Write([]byte(""))
					case strings.HasSuffix(r.URL.Path, "deletions.csv"):
						w.Write([]byte(""))
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				defer emptyChangesServer.Close()

				c = csaf.NewConfig(
					csaf.WithBaseDir(baseDir),
					csaf.WithBaseURL(lo.Must(url.Parse(emptyChangesServer.URL))),
					csaf.WithRetry(0),
				)
				err := c.Update()
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

func createTestArchive(t *testing.T, dir, tmpDir string) {
	t.Helper()
	if dir == "" {
		return
	}

	// Create a file system from the directory
	fsys := os.DirFS(dir)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Add files from the directory file system to the tar archive
	err := tw.AddFS(fsys)
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
