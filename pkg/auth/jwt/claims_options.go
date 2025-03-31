package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type claimsOptions struct{ Claims }

// Represents the options for customizing the token claims.
type ClaimsOption func(*claimsOptions)

// Creates a new instance of tokenOptions with provided options.
// The options can be used to customize the token claims.
func NewClaimsOptions(options ...ClaimsOption) *claimsOptions {
	instance := &claimsOptions{}

	for _, option := range options {
		option(instance)
	}

	return instance
}

// Sets the auth time in the token claims.
// This is used to identify the user associated with the token.
func WithClaimsAuthTime(time time.Time) ClaimsOption {
	return func(o *claimsOptions) {
		o.AuthTime = *jwt.NewNumericDate(time)
	}
}

// Sets the user name in the token claims.
// This is used to identify the user associated with the token.
func WithClaimsName(name string) ClaimsOption {
	return func(o *claimsOptions) {
		o.Name = name
	}
}

// Sets the email in the token claims.
// This is used to identify the email address associated with the token.
func WithClaimsEmail(email string) ClaimsOption {
	return func(o *claimsOptions) {
		o.Email = email
	}
}

// Sets the user roles in the token claims.
// This is used to identify the roles associated with the user in the token.
func WithClaimsRoles(roles []string) ClaimsOption {
	return func(o *claimsOptions) {
		o.Roles = roles
	}
}

// Sets the user picture in the token claims.
// This is used to identify the picture associated with the user in the token.
func WithClaimsPicture(uri string) ClaimsOption {
	return func(o *claimsOptions) {
		o.Picture = uri
	}
}

// Sets the tenant in the token claims.
// This is used to identify the tenant associated with the token.
func WithClaimsTenantId(id string) ClaimsOption {
	return func(o *claimsOptions) {
		o.TenantId = id
	}
}

// Sets the email verified status in the token claims.
// This is used to indicate whether the email address associated with the token has been verified.
func WithClaimsEmailVerified(verified bool) ClaimsOption {
	return func(o *claimsOptions) {
		o.EmailVerified = verified
	}
}
