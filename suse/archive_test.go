package suse

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSavePerYear_invalidID(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, savePerYear("/tmp", fs, "cvrf/suse/suse", "invalid", map[string]string{"k": "v"}))

	files, err := afero.ReadDir(fs, "/tmp/cvrf/suse/suse")
	require.Error(t, err, "no directory should be created for an invalid advisory ID")
	assert.Empty(t, files)
}

func TestSavePerYear_writeError(t *testing.T) {
	fs := afero.NewReadOnlyFs(afero.NewMemMapFs())
	err := savePerYear("/tmp", fs, "cvrf/suse/suse", "SUSE-SU-2019:0048-2", map[string]string{"k": "v"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write file")
}
