package jwt

import (
	"time"
)

// Represents a JSON Web Token (JWT) instance with its configuration and options.
type JWT struct {
	// IdSecret is the secret key used to sign the access token.
	IdSecret string

	// AccessSecret is the secret key used to sign the access token.
	AccessSecret string

	// RefreshSecret is the secret key used to sign the refresh token.
	RefreshSecret string

	// Issuer is the entity that issues the JWT.
	Issuer string

	// Audience is the intended recipient of the JWT.
	Audience []string

	// IdTTL is the time-to-live (TTL) for the ID token.
	// Default is 15 minutes.
	IdTTL time.Duration

	// AccessTTL is the time-to-live (TTL) for the access token.
	// Default is 1 hour.
	AccessTTL time.Duration

	// RefreshTTL is the time-to-live (TTL) for the refresh token.
	// Default is 24 hours.
	RefreshTTL time.Duration
}

// Initializes a new JWT instance with the given parameters.
// It returns an error if any of the parameters are invalid
// (e.g., empty secret, issuer, or audience).
// The JWT instance can be configured with additional options using functional options.
// The default values for the TTLs are as follows:
// - ID token TTL: 15 minutes;
// - Access token TTL: 1 hour;
// - Refresh token TTL: 24 hours.
func NewJWT(
	idSecret string,
	accessSecret string,
	refreshSecret string,
	issuer string,
	audience []string,
	options ...JWTOption,
) (JWT, error) {
	if idSecret == "" {
		return JWT{}, ErrEmptyIdSecret
	}

	if accessSecret == "" {
		return JWT{}, ErrEmptyAccessSecret
	}

	if refreshSecret == "" {
		return JWT{}, ErrEmptyRefreshSecret
	}

	if issuer == "" {
		return JWT{}, ErrEmptyIssuer
	}

	if len(audience) == 0 {
		return JWT{}, ErrNoAudience
	}

	instance := &JWT{
		Issuer:        issuer,
		Audience:      audience,
		IdTTL:         DefaultIdTTL,
		AccessTTL:     DefaultAccessTTL,
		RefreshTTL:    DefaultRefreshTTL,
		AccessSecret:  accessSecret,
		RefreshSecret: refreshSecret,
	}

	for _, option := range options {
		option(instance)
	}

	return *instance, nil
}
