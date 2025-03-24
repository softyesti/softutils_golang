package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jinzhu/copier"
	"github.com/pkg/errors"
)

var _ IJWT = &JWT{}

type IJWT interface {
	// GenAccess generates an access token with the given subject and roles.
	// It returns the signed token as a string or an error if the generation fails.
	GenAccess(subject string, roles []string) (string, error)

	// GenRefresh generates a refresh token with the given subject.
	// It returns the signed token as a string or an error if the generation fails.
	GenRefresh(subject string) (string, error)

	// ParseAccess parses an access token and returns the claims.
	// It verifies the token information and returns an error if verification fails.
	ParseAccess(subject, token string) (AccessClaims, error)

	// ParseRefresh parses a refresh token and returns the claims.
	// It verifies the token information and returns an error if verification fails.
	ParseRefresh(subject, token string) (RefreshClaims, error)
}

type JWT struct {
	secret     string
	issuer     string
	audience   []string
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// Initializes a new JWT instance with the given parameters.
// It returns an error if any of the parameters are invalid
// (e.g., empty secret, issuer, or audience).
// The accessTTL and refreshTTL parameters specify the time-to-live for the access and refresh tokens, respectively.
// If they are not provided, default values are used (1 hour for access and 24 hours for refresh).
func NewJWT(
	issuer string,
	secret string,
	audience []string,
	accessTTL time.Duration,
	refreshTTL time.Duration,
) (JWT, error) {
	var access, refresh time.Duration

	if secret == "" {
		return JWT{}, ErrEmptySecret
	}

	if issuer == "" {
		return JWT{}, ErrEmptyIssuer
	}

	if len(audience) == 0 {
		return JWT{}, ErrNoAudience
	}

	if accessTTL == 0 {
		access = time.Hour
	} else {
		access = accessTTL
	}

	if refreshTTL == 0 {
		refresh = time.Hour * 24
	} else {
		refresh = refreshTTL
	}

	return JWT{
		secret:     secret,
		issuer:     issuer,
		audience:   audience,
		accessTTL:  access,
		refreshTTL: refresh,
	}, nil
}

// GenAccess generates an access token with the given subject and roles.
// It returns the signed token as a string or an error if the generation fails.
func (t *JWT) GenAccess(subject string, roles []string) (string, error) {
	claims, err := t.gen(subject, roles, t.accessTTL)
	if err != nil {
		return "", errors.Wrap(err, ErrClaimsCreation.Error())
	}

	signed, err := t.sign(claims)
	if err != nil {
		return "", errors.Wrap(err, ErrTokenSigning.Error())
	}

	return signed, nil
}

// GenRefresh generates a refresh token with the given subject.
// It returns the signed token as a string or an error if the generation fails.
func (t *JWT) GenRefresh(subject string) (string, error) {
	claims, err := t.gen(subject, []string{}, t.refreshTTL)
	if err != nil {
		return "", errors.Wrap(err, ErrClaimsCreation.Error())
	}

	signed, err := t.sign(claims)
	if err != nil {
		return "", errors.Wrap(err, ErrTokenSigning.Error())
	}

	return signed, nil
}

// ParseAccess parses an access token and returns the claims.
// It verifies the token information and returns an error if verification fails.
func (t *JWT) ParseAccess(subject, token string) (AccessClaims, error) {
	var claims AccessClaims

	parsed, err := t.parse(subject, token)
	if err != nil {
		return claims, errors.Wrap(err, ErrTokenParsing.Error())
	}

	err = copier.Copy(&claims, &parsed)
	if err != nil {
		return claims, errors.Wrap(err, ErrClaimsCopy.Error())
	}

	return claims, nil
}

// ParseRefresh parses a refresh token and returns the claims.
// It verifies the token information and returns an error if verification fails.
func (t *JWT) ParseRefresh(subject, token string) (RefreshClaims, error) {
	var claims RefreshClaims

	parsed, err := t.parse(subject, token)
	if err != nil {
		return claims, errors.Wrap(err, ErrTokenParsing.Error())
	}

	err = copier.Copy(&claims, &parsed)
	if err != nil {
		return claims, errors.Wrap(err, ErrClaimsCopy.Error())
	}

	return claims, nil
}

func (t *JWT) gen(
	subject string,
	roles []string,
	TTL time.Duration,
) (claims, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(TTL)

	if subject == "" {
		return claims{}, ErrEmptySubject
	}

	if now.After(expiresAt) {
		return claims{}, ErrExpiredToken
	}

	id, err := uuid.NewRandom()
	if err != nil {
		return claims{}, errors.Wrap(err, ErrUUIDGeneration.Error())
	}

	return claims{
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        id.String(),
			Subject:   subject,
			Issuer:    t.issuer,
			Audience:  t.audience,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}, nil
}

func (t *JWT) sign(claims claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(t.secret))
	if err != nil {
		return "", errors.Wrap(err, ErrTokenSigning.Error())
	}

	return signed, nil
}

func (t *JWT) parse(subject, token string) (claims, error) {
	if token == "" {
		return claims{}, ErrEmptyToken
	}

	verifies, err := t.verify(subject)
	if err != nil {
		return claims{}, errors.Wrap(err, ErrTokenVerification.Error())
	}

	parsed, err := jwt.ParseWithClaims(
		token,
		&claims{},
		func(*jwt.Token) (any, error) {
			return []byte(t.secret), nil
		},
		verifies...,
	)

	if err != nil {
		return claims{}, errors.Wrap(err, ErrTokenParsing.Error())
	}

	if !parsed.Valid {
		return claims{}, ErrTokenVerification
	}

	obj, ok := parsed.Claims.(*claims)
	if !ok {
		return claims{}, ErrTokenParsing
	}

	return *obj, nil
}

func (t *JWT) verify(subject string) ([]jwt.ParserOption, error) {
	if subject == "" {
		return nil, ErrEmptySubject
	}

	options := []jwt.ParserOption{
		jwt.WithIssuedAt(),
		jwt.WithSubject(subject),
		jwt.WithIssuer(t.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
	}

	for _, audience := range t.audience {
		options = append(options, jwt.WithAudience(audience))
	}

	return options, nil
}
