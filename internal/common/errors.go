package common

import "errors"

var (
	ImplementationErr = errors.New("internal error") // should never happen, usually cause a panic
)
