package jwt

import (
	"github.com/jinzhu/copier"
	"github.com/pkg/errors"
)

// Generates an id token with the given subject and roles.
// It returns the signed token as a string or an error if the generation fails.
func (t *JWT) GenIdToken(
	subject string,
	options *idTokenOptions,
) (string, error) {
	if subject == "" {
		return "", ErrEmptySubject
	}

	registered, err := t.gen(subject, t.IdTTL)
	if err != nil {
		return "", errors.Wrap(err, ErrClaimsCreation.Error())
	}

	claims := options.IdTokenClaims
	claims.RegisteredClaims = registered

	signed, err := t.sign(t.IdSecret, claims)
	if err != nil {
		return "", errors.Wrap(err, ErrTokenSigning.Error())
	}

	return signed, nil
}

// Parses an id token and returns the claims.
// It verifies the token information and returns an error if verification fails.
func (t *JWT) ParseIdToken(token string) (IdTokenClaims, error) {
	claims := IdTokenClaims{}

	parsed, err := t.parse(t.IdSecret, token, &claims)
	if err != nil {
		return claims, errors.Wrap(err, ErrTokenParsing.Error())
	}

	err = copier.Copy(&claims, &parsed)
	if err != nil {
		return claims, errors.Wrap(err, ErrClaimsCopy.Error())
	}

	return claims, nil
}
