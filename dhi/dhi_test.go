package dhi

import (
	"archive/tar"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/utils"
)

func record(id string) string {
	return `{
  "id":"` + id + `",
  "affected":[{"package":{"ecosystem":"Docker Hardened Images:Alpine:3.24","name":"pkg","purl":"pkg:apk/dhi/pkg"}}]
}`
}

// writeFiles creates files below root from a map of slash-separated relative paths to contents.
func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
		require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	}
}

// serveArchive serves files as the GitHub archive of the advisories main branch.
func serveArchive(t *testing.T, files map[string]string) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		gz := gzip.NewWriter(w)
		tw := tar.NewWriter(gz)
		for name, content := range files {
			require.NoError(t, tw.WriteHeader(&tar.Header{
				Name: "advisories-main/" + name, Mode: 0600, Size: int64(len(content)), Typeflag: tar.TypeReg,
			}))
			_, err := tw.Write([]byte(content))
			require.NoError(t, err)
		}
		require.NoError(t, tw.Close())
		require.NoError(t, gz.Close())
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestUpdater_Update(t *testing.T) {
	ts := serveArchive(t, map[string]string{
		"dhi/osv/2026/DHI-2026-0001.json":             record("DHI-2026-0001"),
		"dhi/osv/2026/DHI-2026-0001.json.asc":         "-----BEGIN PGP SIGNATURE-----",
		"dhi/osv/2026/DHI-2026-0001.json.sha256":      "0000  dhi/osv/2026/DHI-2026-0001.json",
		"dhi/osv/2026/DHI-2026-0001.json.sha256.asc":  "-----BEGIN PGP SIGNATURE-----",
		"dhi/osv/2027/DHI-2027-0001.json":             record("DHI-2027-0001"),
		"dhi/vex/2026/DHI-2026-0001.json":             `{"@id":"https://dhi.io/vex/DHI-2026-0001.json"}`,
		"osv/other/OTHER-0001.json":                   record("OTHER-0001"),
		"integration/examples/osv/DHI-9999-0001.json": record("DHI-9999-0001"),
	})
	vulnListDir := t.TempDir()
	previous := utils.VulnListDir()
	utils.SetVulnListDir(vulnListDir)
	t.Cleanup(func() { utils.SetVulnListDir(previous) })

	u := Updater{url: ts.URL + "/main.tar.gz//advisories-main/dhi/osv"}
	require.NoError(t, u.Update())

	var got []string
	target := filepath.Join(vulnListDir, "dhi")
	require.NoError(t, filepath.WalkDir(target, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		rel, err := filepath.Rel(target, path)
		got = append(got, filepath.ToSlash(rel))
		return err
	}))
	assert.ElementsMatch(t, []string{"2026/DHI-2026-0001.json", "2027/DHI-2027-0001.json"}, got)
}

func TestUpdateFromDir(t *testing.T) {
	t.Run("keeps year directories and skips sidecars", func(t *testing.T) {
		root := t.TempDir()
		source := filepath.Join(root, "osv")
		target := filepath.Join(root, "vuln-list", "dhi")
		writeFiles(t, source, map[string]string{
			"2026/DHI-2026-0001.json":        record("DHI-2026-0001"),
			"2026/DHI-2026-0001.json.sha512": "0000  dhi/osv/2026/DHI-2026-0001.json",
			"2027/DHI-2027-0001.json":        record("DHI-2027-0001"),
		})

		require.NoError(t, updateFromDir(source, target))
		for _, name := range []string{"2026/DHI-2026-0001.json", "2027/DHI-2027-0001.json"} {
			_, err := os.Stat(filepath.Join(target, filepath.FromSlash(name)))
			require.NoError(t, err, name)
		}
		_, err := os.Stat(filepath.Join(target, "2026", "DHI-2026-0001.json.sha512"))
		assert.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("duplicate advisory across years", func(t *testing.T) {
		root := t.TempDir()
		source := filepath.Join(root, "osv")
		writeFiles(t, source, map[string]string{
			"2026/DHI-2026-0001.json": record("DHI-2026-0001"),
			"2027/DHI-2026-0001.json": record("DHI-2026-0001"),
		})

		err := updateFromDir(source, filepath.Join(root, "vuln-list", "dhi"))
		require.ErrorContains(t, err, "duplicate DHI advisory DHI-2026-0001")
	})

	t.Run("empty feed", func(t *testing.T) {
		root := t.TempDir()
		source := filepath.Join(root, "osv")
		require.NoError(t, os.MkdirAll(filepath.Join(source, "2026"), 0700))

		err := updateFromDir(source, filepath.Join(root, "vuln-list", "dhi"))
		require.ErrorContains(t, err, "no DHI OSV advisories found under dhi/osv")
	})

	t.Run("invalid snapshot preserves previous data", func(t *testing.T) {
		root := t.TempDir()
		source := filepath.Join(root, "osv")
		target := filepath.Join(root, "vuln-list", "dhi")
		writeFiles(t, source, map[string]string{"2026/bad.json": `{"id":`})
		writeFiles(t, target, map[string]string{"2026/known-good.json": record("DHI-2026-0001")})

		err := updateFromDir(source, target)
		require.ErrorContains(t, err, "invalid DHI OSV record")
		_, statErr := os.Stat(filepath.Join(target, "2026", "known-good.json"))
		require.NoError(t, statErr)
	})
}
