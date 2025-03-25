package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

var _ IJWT = &JWT{}

type IJWT interface {
	// Generates an ID token with the given subject.
	// It returns the signed token as a string or an error if the generation fails.
	GenIdToken(subject string, options *idTokenOptions) (string, error)

	// Generates an access token with the given subject and roles.
	// It returns the signed token as a string or an error if the generation fails.
	GenAccessToken(subject string, options *accessTokenOptions) (string, error)

	// Generates a refresh token with the given subject.
	// It returns the signed token as a string or an error if the generation fails.
	GenRefreshToken(subject string, options *refreshTokenOptions) (string, error)

	// Parses an ID token and returns the claims.
	// It verifies the token information and returns an error if verification fails.
	ParseIdToken(token string) (IdTokenClaims, error)

	// Parses an access token and returns the claims.
	// It verifies the token information and returns an error if verification fails.
	ParseAccessToken(token string) (AccessTokenClaims, error)

	// Parses a refresh token and returns the claims.
	// It verifies the token information and returns an error if verification fails.
	ParseRefreshToken(token string) (RefreshTokenClaims, error)
}

func (t *JWT) gen(
	subject string,
	TTL time.Duration,
) (jwt.RegisteredClaims, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(TTL)

	if subject == "" {
		return jwt.RegisteredClaims{}, ErrEmptySubject
	}

	if now.After(expiresAt) {
		return jwt.RegisteredClaims{}, ErrExpiredToken
	}

	id, err := uuid.NewRandom()
	if err != nil {
		return jwt.RegisteredClaims{},
			errors.Wrap(err, ErrUUIDGeneration.Error())
	}

	return jwt.RegisteredClaims{
		ID:        id.String(),
		Subject:   subject,
		Issuer:    t.Issuer,
		Audience:  t.Audience,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
	}, nil
}

func (t *JWT) sign(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(t.Secret))
	if err != nil {
		return "", errors.Wrap(err, ErrTokenSigning.Error())
	}

	return signed, nil
}

func (t *JWT) parse(token string, claims jwt.Claims) (jwt.Claims, error) {
	if token == "" {
		return jwt.RegisteredClaims{}, ErrEmptyToken
	}

	options := []jwt.ParserOption{
		jwt.WithIssuedAt(),
		jwt.WithIssuer(t.Issuer),
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
	}

	for _, audience := range t.Audience {
		options = append(options, jwt.WithAudience(audience))
	}

	parsed, err := jwt.ParseWithClaims(
		token,
		claims,
		func(*jwt.Token) (any, error) {
			return []byte(t.Secret), nil
		},
		options...,
	)

	if err != nil {
		return jwt.RegisteredClaims{}, errors.Wrap(err, ErrTokenParsing.Error())
	}

	if !parsed.Valid {
		return jwt.RegisteredClaims{}, ErrTokenVerification
	}

	return parsed.Claims, nil
}
