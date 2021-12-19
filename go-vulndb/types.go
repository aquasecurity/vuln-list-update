package govulndb

import (
	"golang.org/x/vuln/osv"
)

type Entry struct {
	// We need to add this field on our end until the following issue will be addressed.
	// https://github.com/golang/go/issues/50006
	Module string `json:"module"`

	osv.Entry
}
