package jwt

import (
	"github.com/golang-jwt/jwt/v5"
)

// Represents the claims for the ID token.
type IdTokenClaims struct {
	jwt.RegisteredClaims
	AuthTime      jwt.NumericDate `json:"auth_time"`
	Name          string          `json:"name,omitempty"`
	Email         string          `json:"email,omitempty"`
	Roles         []string        `json:"roles,omitempty"`
	Picture       string          `json:"picture,omitempty"`
	TenantId      string          `json:"tenant_id,omitempty"`
	EmailVerified bool            `json:"email_verified,omitempty"`
}

// Validates the ID token claims.
func (claims *IdTokenClaims) Validate() error {
	if claims.AuthTime.IsZero() {
		return ErrEmptyAuthTime
	}

	return nil
}

// Represents the claims for the access token.
type AccessTokenClaims struct {
	jwt.RegisteredClaims
	Roles    []string `json:"roles,omitempty"`
	Email    string   `json:"email,omitempty"`
	TenantId string   `json:"tenant_id,omitempty"`
}

// Validates the access token claims.
func (claims *AccessTokenClaims) Validate() error {
	return nil
}

// Represents the claims for the refresh token.
type RefreshTokenClaims struct {
	jwt.RegisteredClaims
	TenantId string `json:"tenant_id,omitempty"`
}

// Validates the refresh token claims.
func (claims *RefreshTokenClaims) Validate() error {
	return nil
}
