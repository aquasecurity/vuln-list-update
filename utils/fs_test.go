package utils_test

import (
	"errors"
	"math"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/vuln-list-update/utils"
)

func TestWriteJSON(t *testing.T) {
	testCases := []struct {
		name          string
		fs            afero.Fs
		inputData     interface{}
		expectedData  string
		expectedError error
	}{
		{
			name: "happy path",
			fs:   afero.NewMemMapFs(),
			inputData: struct {
				A string
				B int
			}{A: "foo", B: 1},
			expectedData: "{\n  \"A\": \"foo\",\n  \"B\": 1\n}",
		},
		{
			name:          "sad path: fs.AppFs.Create returns an error",
			fs:            afero.NewReadOnlyFs(afero.NewMemMapFs()),
			expectedError: errors.New("unable to create a directory: operation not permitted"),
		},
		{
			name:          "sad path: bad json input data",
			fs:            afero.NewMemMapFs(),
			inputData:     math.NaN(),
			expectedError: errors.New("failed to marshal JSON: json: unsupported value: NaN"),
		},
	}

	for _, tc := range testCases {
		err := utils.WriteJSON(tc.fs, "dir", "file", tc.inputData)
		switch {
		case tc.expectedError != nil:
			require.NotNil(t, err)
			assert.Equal(t, tc.expectedError.Error(), err.Error(), tc.name)
			return
		default:
			assert.NoError(t, err, tc.name)
		}

		actual, err := afero.ReadFile(tc.fs, "dir/file")
		assert.NoError(t, err, tc.name)
		assert.Equal(t, tc.expectedData, string(actual), tc.name)
	}
}
