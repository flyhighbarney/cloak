package audit

import "errors"

// errorsIs is a local alias to keep the recorder package tidy.
func errorsIs(err, target error) bool { return errors.Is(err, target) }
