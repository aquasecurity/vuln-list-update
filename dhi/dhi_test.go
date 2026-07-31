package dhi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validRecord = `{
  "id":"DHI-CVE-2026-0001-pkg",
  "affected":[{"package":{"ecosystem":"Docker Hardened Images","name":"pkg"}}]
}`

func TestUpdateFromDir(t *testing.T) {
	t.Run("copies only osv/dhi JSON", func(t *testing.T) {
		root := t.TempDir()
		source := filepath.Join(root, "advisories-main")
		target := filepath.Join(root, "vuln-list", "dhi")
		require.NoError(t, os.MkdirAll(filepath.Join(source, "osv", "dhi"), 0700))
		require.NoError(t, os.MkdirAll(filepath.Join(source, "osv", "other"), 0700))
		require.NoError(t, os.WriteFile(filepath.Join(source, "osv", "dhi", "DHI.json"), []byte(validRecord), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(source, "osv", "other", "other.json"), []byte(validRecord), 0600))

		require.NoError(t, updateFromDir(source, target))
		_, err := os.Stat(filepath.Join(target, "DHI.json"))
		require.NoError(t, err)
		_, err = os.Stat(filepath.Join(target, "other.json"))
		assert.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("invalid snapshot preserves previous data", func(t *testing.T) {
		root := t.TempDir()
		source := filepath.Join(root, "source", "osv", "dhi")
		target := filepath.Join(root, "vuln-list", "dhi")
		require.NoError(t, os.MkdirAll(source, 0700))
		require.NoError(t, os.MkdirAll(target, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(source, "bad.json"), []byte(`{"id":`), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(target, "known-good.json"), []byte(validRecord), 0600))

		err := updateFromDir(filepath.Dir(filepath.Dir(source)), target)
		require.ErrorContains(t, err, "invalid DHI OSV record")
		_, statErr := os.Stat(filepath.Join(target, "known-good.json"))
		require.NoError(t, statErr)
	})
}
