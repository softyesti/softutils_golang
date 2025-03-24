package jwt

import "github.com/golang-jwt/jwt/v5"

type claims struct {
	jwt.RegisteredClaims
	Roles []string `json:"roles,omitempty"`
}

type AccessClaims struct {
	jwt.RegisteredClaims
	Roles []string `json:"roles,omitempty"`
}

type RefreshClaims struct {
	jwt.RegisteredClaims
}
