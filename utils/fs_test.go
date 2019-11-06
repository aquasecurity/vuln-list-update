package utils

import (
	"errors"
	"io/ioutil"
	"math"
	"os"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

type fakeMemFS struct {
	create func(string) (afero.File, error)
}

func (ffs fakeMemFS) Create(name string) (afero.File, error) {
	if ffs.create != nil {
		return ffs.create(name)
	}

	return ioutil.TempFile("", "fakeMemFS-*.file")
}

func (ffs fakeMemFS) Mkdir(name string, perm os.FileMode) error {
	panic("implement me")
}

func (ffs fakeMemFS) MkdirAll(path string, perm os.FileMode) error {
	panic("implement me")
}

func (ffs fakeMemFS) Open(name string) (afero.File, error) {
	panic("implement me")
}

func (ffs fakeMemFS) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	panic("implement me")
}

func (ffs fakeMemFS) Remove(name string) error {
	panic("implement me")
}

func (ffs fakeMemFS) RemoveAll(path string) error {
	panic("implement me")
}

func (ffs fakeMemFS) Rename(oldname, newname string) error {
	panic("implement me")
}

func (ffs fakeMemFS) Stat(name string) (os.FileInfo, error) {
	panic("implement me")
}

func (ffs fakeMemFS) Name() string {
	panic("implement me")
}

func (ffs fakeMemFS) Chmod(name string, mode os.FileMode) error {
	panic("implement me")
}

func (ffs fakeMemFS) Chtimes(name string, atime time.Time, mtime time.Time) error {
	panic("implement me")
}

func TestFs_WriteJSON(t *testing.T) {
	testCases := []struct {
		name          string
		memfs         Fs
		inputData     interface{}
		expectedError error
	}{
		{
			name:      "happy path",
			memfs:     NewFs(fakeMemFS{}),
			inputData: `{}`,
		},
		{
			name: "sad path: fs.AppFs.Create returns an error",
			memfs: NewFs(fakeMemFS{
				create: func(s string) (file afero.File, e error) {
					return nil, errors.New("cannot create file")
				},
			}),
			expectedError: errors.New("unable to open a file: cannot create file"),
		},
		{
			name:          "sad path: bad json input data",
			memfs:         NewFs(fakeMemFS{}),
			inputData:     math.NaN(),
			expectedError: errors.New("failed to marshal JSON: json: unsupported value: NaN"),
		},
	}

	for _, tc := range testCases {
		err := tc.memfs.WriteJSON("foo", tc.inputData)
		switch {
		case tc.expectedError != nil:
			assert.Equal(t, tc.expectedError.Error(), err.Error(), tc.name)
		default:
			assert.NoError(t, err, tc.name)
		}
	}

}
