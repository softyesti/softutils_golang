package jwt

import (
	"github.com/jinzhu/copier"
	"github.com/pkg/errors"
)

// Generates a refresh token with the given subject.
// It returns the signed token as a string or an error if the generation fails.
func (t *JWT) GenRefreshToken(
	subject string,
	options *claimsOptions,
) (string, error) {
	if subject == "" {
		return "", ErrEmptySubject
	}

	registered, err := t.gen(subject, t.IdTTL)
	if err != nil {
		return "", errors.Wrap(err, ErrClaimsCreation.Error())
	}

	claims := options.Claims
	claims.RegisteredClaims = registered

	signed, err := t.sign(t.RefreshSecret, claims)
	if err != nil {
		return "", errors.Wrap(err, ErrTokenSigning.Error())
	}

	return signed, nil
}

// Parses a refresh token and returns the claims.
// It verifies the token information and returns an error if verification fails.
func (t *JWT) ParseRefreshToken(token string) (RefreshTokenClaims, error) {
	claims := RefreshTokenClaims{}

	parsed, err := t.parse(t.RefreshSecret, token, &claims)
	if err != nil {
		return claims, errors.Wrap(err, ErrTokenParsing.Error())
	}

	err = copier.Copy(&claims, &parsed)
	if err != nil {
		return claims, errors.Wrap(err, ErrClaimsCopy.Error())
	}

	return claims, nil
}
