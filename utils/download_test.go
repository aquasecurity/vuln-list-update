package utils_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/utils"
)

func TestDownloadToTempDir(t *testing.T) {
	tests := []struct {
		name         string
		filePath     string
		wantFileName string
		want         string
		wantErr      string
	}{
		{
			name:         "happy path",
			filePath:     "testdata/test.tar.gz",
			wantFileName: "test.txt",
			want:         "test",
		},
		{
			name:     "sad path",
			filePath: "testdata/unknown.tar.gz",
			wantErr:  "bad response code: 404",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Println(r.URL.Path)
				http.ServeFile(w, r, filepath.Join(".", r.URL.Path))
			}))

			u, err := url.Parse(ts.URL)
			require.NoError(t, err)

			u.Path = path.Join(u.Path, tt.filePath)
			tmpDir, err := utils.DownloadToTempDir(context.Background(), u.String())
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)

			got, err := os.ReadFile(filepath.Join(tmpDir, tt.wantFileName))
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestDownloadToTempFile(t *testing.T) {
	tests := []struct {
		name         string
		filePath     string
		wantFileName string
		want         string
		wantErr      string
	}{
		{
			name:     "happy path",
			filePath: "testdata/test.txt.gz",
			want:     "test",
		},
		{
			name:     "sad path",
			filePath: "testdata/unknown.tar.gz",
			wantErr:  "bad response code: 404",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Println(r.URL.Path)
				http.ServeFile(w, r, filepath.Join(".", r.URL.Path))
			}))

			u, err := url.Parse(ts.URL)
			require.NoError(t, err)

			u.Path = path.Join(u.Path, tt.filePath)
			tmpFile, err := utils.DownloadToTempFile(context.Background(), u.String())
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)

			got, err := os.ReadFile(tmpFile)
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}
