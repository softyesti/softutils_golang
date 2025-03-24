package hash

import (
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

var _ IHash = &Hash{}

type IHash interface {
	Generate(password string) (string, error)
	Compare(password, hash string) (bool, error)
}

type Hash struct {
	cost uint
}

// Initializes a new Hash instance with the given cost.
func NewHash(cost uint) Hash {
	if cost == 0 {
		cost = 15
	}

	return Hash{
		cost: cost,
	}
}

// Generates a hash from the given password.
func (h *Hash) Generate(password string) (string, error) {
	if password == "" {
		return "", ErrEmptyPassword
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), int(h.cost))
	if err != nil {
		return "", errors.Wrap(err, ErrHashGeneration.Error())
	}

	return string(hash), nil
}

// Compares a password with a hash.
func (h *Hash) Compare(password string, hash string) (bool, error) {
	if password == "" {
		return false, ErrEmptyPassword
	}

	if hash == "" {
		return false, ErrEmptyHash
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return false, errors.Wrap(err, ErrHashCompare.Error())
	}

	return true, nil
}
