package jwt

import "time"

type JWTOption func(*JWT)

// Sets the ID token time-to-live (TTL) for the JWT instance.
// The ID token TTL determines how long the ID token is valid before it expires.
// Default is 15 minutes.
func WithIdTTL(ttl time.Duration) JWTOption {
	if ttl == 0 {
		ttl = DefaultIdTTL
	}

	return func(jwt *JWT) {
		jwt.IdTTL = ttl
	}
}

// Sets the access token time-to-live (TTL) for the JWT instance.
// The access token TTL determines how long the access token is valid before it expires.
// Default is 1 hour.
func WithAccessTTL(ttl time.Duration) JWTOption {
	if ttl == 0 {
		ttl = DefaultAccessTTL
	}

	return func(jwt *JWT) {
		jwt.AccessTTL = ttl
	}
}

// Sets the refresh token time-to-live (TTL) for the JWT instance.
// The refresh token TTL determines how long the refresh token is valid before it expires.
// Default is 24 hours.
func WithRefreshTTL(ttl time.Duration) JWTOption {
	if ttl == 0 {
		ttl = DefaultRefreshTTL
	}

	return func(jwt *JWT) {
		jwt.RefreshTTL = ttl
	}
}
