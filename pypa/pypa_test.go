package pypa

import (
	"os"
	"testing"
)

func Test_Update(t *testing.T) {
	pypa := NewPypa()
	os.RemoveAll(pypa.opts.dir)
	err := pypa.Update()
	if err != nil {
		t.Errorf("error: %v\n", err)
	}
}
