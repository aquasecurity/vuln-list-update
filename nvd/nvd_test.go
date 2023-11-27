package nvd

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUpdate(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "happy path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//httptest.NewServer(http.FileServer(http.Dir("testdata")))

			u := NewUpdater()
			err := u.Update()
			assert.NoError(t, err)

		})
	}
}
