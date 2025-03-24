package hash

import "github.com/pkg/errors"

var (
	ErrEmptyHash      = errors.New("hash: provided hash is empty")
	ErrEmptyPassword  = errors.New("hash: provided password is empty")
	ErrHashCompare    = errors.New("hash: failed to compare hash")
	ErrHashGeneration = errors.New("hash: failed to generate hash")
)
