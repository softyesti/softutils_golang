package jwt

import (
	"github.com/pkg/errors"
)

var (
	ErrEmptyIdSecret      = errors.New("jwt: provided id token secret is empty")
	ErrEmptyAccessSecret  = errors.New("jwt: provided access token secret is empty")
	ErrEmptyRefreshSecret = errors.New("jwt: provided refresh token secret is empty")
	ErrEmptyIssuer        = errors.New("jwt: provided issuer is empty")
	ErrNoAudience         = errors.New("jwt: no audience provided")
	ErrNilSigningMethod   = errors.New("jwt: signing method is nil")
	ErrEmptySubject       = errors.New("jwt: provided subject is empty")
	ErrExpiredToken       = errors.New("jwt: token expiration time is in the past")
	ErrUUIDGeneration     = errors.New("jwt: failed to generate UUID")
	ErrClaimsCreation     = errors.New("jwt: failed to create claims")
	ErrTokenSigning       = errors.New("jwt: failed to sign token")
	ErrEmptyToken         = errors.New("jwt: provided token is empty")
	ErrTokenParsing       = errors.New("jwt: failed to parse token")
	ErrTokenVerification  = errors.New("jwt: token verification failed")
	ErrClaimsCopy         = errors.New("jwt: failed to copy claims data")
	ErrEmptyAuthTime      = errors.New("jwt: auth time is empty")
)
