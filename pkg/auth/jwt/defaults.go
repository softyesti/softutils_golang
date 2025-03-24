package jwt

import "time"

var (
	// Default ID token time-to-live (TTL) is 15 minutes.
	DefaultIdTTL = time.Minute * 15

	// Default access token time-to-live (TTL) is 1 hour.
	DefaultAccessTTL = time.Hour * 1

	// Default refresh token time-to-live (TTL) is 24 hours.
	DefaultRefreshTTL = time.Hour * 24
)
