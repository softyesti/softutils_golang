package main

import (
	"fmt"

	"github.com/softyesti/softutils_golang/pkg/auth/jwt"
)

func main() {
	// Create a new JWT instance
	instance, err := jwt.NewJWT(
		"secret",
		"issuer",
		[]string{"audience"},
		jwt.WithIdTTL(jwt.DefaultIdTTL),
		jwt.WithAccessTTL(jwt.DefaultAccessTTL),
		jwt.WithRefreshTTL(jwt.DefaultRefreshTTL),
	)
	if err != nil {
		panic(err)
	}

	// Generate a new ID token
	idTokenOptions := jwt.NewIdTokenOptions(
		jwt.WithIdTokenName("John Doe"),
		jwt.WithIdTokenEmail("john.doe@email.com"),
	)

	idToken, err := instance.GenIdToken("subject", idTokenOptions)
	if err != nil {
		panic(err)
	}

	// Generate a new Access token
	accessTokenOptions := jwt.NewAccessTokenOptions(
		jwt.WithAccessTokenRoles([]string{"admin", "user"}),
		jwt.WithAccessTokenTenantId("tenant-id"),
	)

	accessToken, err := instance.GenAccessToken("subject", accessTokenOptions)
	if err != nil {
		panic(err)
	}

	// Generate a new Refresh token
	refreshTokenOptions := jwt.NewRefreshTokenOptions(
		jwt.WithRefreshTokenTenantId("tenant-id"),
	)

	refreshToken, err := instance.GenRefreshToken("subject", refreshTokenOptions)
	if err != nil {
		panic(err)
	}

	// Print the generated tokens
	fmt.Println("ID Token:", idToken)
	fmt.Println("Access Token:", accessToken)
	fmt.Println("Refresh Token:", refreshToken)

	// Parse the ID token
	idClaims, err := instance.ParseIdToken(idToken)
	if err != nil {
		panic(err)
	}

	// Parse the Access token
	accessClaims, err := instance.ParseAccessToken(accessToken)
	if err != nil {
		panic(err)
	}

	// Parse the Refresh token
	refreshClaims, err := instance.ParseRefreshToken(refreshToken)
	if err != nil {
		panic(err)
	}

	// Print the parsed claims
	fmt.Println("ID Claims:", idClaims)
	fmt.Println("Access Claims:", accessClaims)
	fmt.Println("Refresh Claims:", refreshClaims)
}
