package jwt

import (
	"github.com/jinzhu/copier"
	"github.com/pkg/errors"
)

// Generates an access token with the given subject and roles.
// It returns the signed token as a string or an error if the generation fails.
func (t *JWT) GenAccessToken(
	subject string,
	options *accessTokenOptions,
) (string, error) {
	if subject == "" {
		return "", ErrEmptySubject
	}

	registered, err := t.gen(subject, t.AccessTTL)
	if err != nil {
		return "", errors.Wrap(err, ErrClaimsCreation.Error())
	}

	claims := options.AccessTokenClaims
	claims.RegisteredClaims = registered

	signed, err := t.sign(claims)
	if err != nil {
		return "", errors.Wrap(err, ErrTokenSigning.Error())
	}

	return signed, nil
}

// Parses an access token and returns the claims.
// It verifies the token information and returns an error if verification fails.
func (t *JWT) ParseAccessToken(token string) (AccessTokenClaims, error) {
	claims := AccessTokenClaims{}

	parsed, err := t.parse(token, &claims)
	if err != nil {
		return claims, errors.Wrap(err, ErrTokenParsing.Error())
	}

	err = copier.Copy(&claims, &parsed)
	if err != nil {
		return claims, errors.Wrap(err, ErrClaimsCopy.Error())
	}

	return claims, nil
}
