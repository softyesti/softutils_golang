package auth

import "golang.org/x/crypto/bcrypt"

type AuthEncryptUtil struct{}

type Encrypted struct {
	Hash    string `json:"hash"`
	Value   string `json:"value"`
	IsValid bool   `json:"isValid"`
}

// Encrypts a value using bcrypt and returns the hash and the original value
func (util *AuthEncryptUtil) Encrypt(
	value string,
) (Encrypted, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(value), 14)
	if err != nil {
		return Encrypted{}, err
	}

	return Encrypted{
		Hash:    string(bytes),
		Value:   value,
		IsValid: false,
	}, nil
}

// Compares the hash generated by bcrypt with a bare value
func (util *AuthEncryptUtil) Compare(
	hash string,
	value string,
) (Encrypted, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(value))
	if err != nil {
		return Encrypted{}, err
	}

	return Encrypted{
		Hash:    hash,
		Value:   value,
		IsValid: true,
	}, nil
}