package utils

import (
	"errors"
	"math"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func TestFs_WriteJSON(t *testing.T) {
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
			expectedError: errors.New("unable to open a file: operation not permitted"),
		},
		{
			name:          "sad path: bad json input data",
			fs:            afero.NewMemMapFs(),
			inputData:     math.NaN(),
			expectedError: errors.New("failed to marshal JSON: json: unsupported value: NaN"),
		},
	}

	for _, tc := range testCases {
		fs := NewFs(tc.fs)
		err := fs.WriteJSON("foo", tc.inputData)
		switch {
		case tc.expectedError != nil:
			assert.Equal(t, tc.expectedError.Error(), err.Error(), tc.name)
			return
		default:
			assert.NoError(t, err, tc.name)
		}

		actual, err := afero.ReadFile(tc.fs, "foo")
		assert.NoError(t, err, tc.name)
		assert.Equal(t, tc.expectedData, string(actual), tc.name)
	}
}
