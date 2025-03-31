package jwt

type accessTokenOptions struct{ AccessTokenClaims }

// Represents the options for customizing the access token claims.
type AccessTokenOption func(*accessTokenOptions)

func NewAccessTokenOptions(options ...AccessTokenOption) *accessTokenOptions {
	instance := &accessTokenOptions{
		AccessTokenClaims: AccessTokenClaims{},
	}

	for _, option := range options {
		option(instance)
	}

	return instance
}

// Sets the user roles in the access token claims.
// This is used to identify the roles associated with the user in the access token.
func WithAccessTokenRoles(roles []string) AccessTokenOption {
	return func(o *accessTokenOptions) {
		o.AccessTokenClaims.Roles = roles
	}
}

// Sets the email in the access token claims.
// This is used to identify the email address associated with the access token.
func WithAccessTokenEmail(email string) AccessTokenOption {
	return func(o *accessTokenOptions) {
		o.AccessTokenClaims.Email = email
	}
}

// Sets the tenant ID in the access token claims.
// This is used to identify the tenant associated with the access token.
func WithAccessTokenTenantId(tenantId string) AccessTokenOption {
	return func(o *accessTokenOptions) {
		o.AccessTokenClaims.TenantId = tenantId
	}
}
