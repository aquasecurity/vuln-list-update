package eol

import "golang.org/x/xerrors"

type EolSrc interface {
	Update() error
	Name() string
}

func AllEolDatesUpdate() error {
	for _, src := range all {
		if err := src.Update(); err != nil {
			return xerrors.Errorf("unable to update %q EOL dates", src.Name())
		}
	}
	return nil
}
