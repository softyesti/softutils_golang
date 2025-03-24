package jwt

type refreshTokenOptions struct{ RefreshTokenClaims }

// Represents the options for customizing the refresh token claims.
type RefreshTokenOption func(*refreshTokenOptions)

// Creates a new instance of refreshTokenOptions with provided options.
// The options can be used to customize the refresh token claims.
func NewRefreshTokenOptions(options ...RefreshTokenOption) *refreshTokenOptions {
	instance := &refreshTokenOptions{
		RefreshTokenClaims: RefreshTokenClaims{},
	}

	for _, option := range options {
		option(instance)
	}

	return instance
}

// Sets the tenant ID in the refresh token claims.
// This is used to identify the tenant associated with the refresh token.
func WithRefreshTokenTenantId(tenantId string) RefreshTokenOption {
	return func(o *refreshTokenOptions) {
		o.RefreshTokenClaims.TenantId = tenantId
	}
}
