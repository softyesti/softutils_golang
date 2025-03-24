package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type idTokenOptions struct{ IdTokenClaims }

// Represents the options for customizing the ID token claims.
type IdTokenOption func(*idTokenOptions)

// Creates a new instance of idTokenOptions with provided options.
// The options can be used to customize the ID token claims.
func NewIdTokenOptions(options ...IdTokenOption) *idTokenOptions {
	now := time.Now().UTC()

	instance := &idTokenOptions{
		IdTokenClaims: IdTokenClaims{
			AuthTime: *jwt.NewNumericDate(now),
		},
	}

	for _, option := range options {
		option(instance)
	}

	return instance
}

// Sets the user name in the ID token claims.
// This is used to identify the user associated with the ID token.
func WithIdTokenName(name string) IdTokenOption {
	return func(o *idTokenOptions) {
		o.IdTokenClaims.Name = name
	}
}

// Sets the email in the ID token claims.
// This is used to identify the email address associated with the ID token.
func WithIdTokenEmail(email string) IdTokenOption {
	return func(o *idTokenOptions) {
		o.IdTokenClaims.Email = email
	}
}

// Sets the user roles in the ID token claims.
// This is used to identify the roles associated with the user in the ID token.
func WithIdTokenRoles(roles []string) IdTokenOption {
	return func(o *idTokenOptions) {
		o.IdTokenClaims.Roles = roles
	}
}

// Sets the user picture in the ID token claims.
// This is used to identify the picture associated with the user in the ID token.
func WithIdTokenPicture(picture string) IdTokenOption {
	return func(o *idTokenOptions) {
		o.IdTokenClaims.Picture = picture
	}
}

// Sets the tenant ID in the ID token claims.
// This is used to identify the tenant associated with the ID token.
func WithIdTokenTenantId(tenantId string) IdTokenOption {
	return func(o *idTokenOptions) {
		o.IdTokenClaims.TenantId = tenantId
	}
}

// Sets the email verified status in the ID token claims.
// This is used to indicate whether the email address associated with the ID token has been verified.
func WithIdTokenEmailVerified(emailVerified bool) IdTokenOption {
	return func(o *idTokenOptions) {
		o.IdTokenClaims.EmailVerified = emailVerified
	}
}
