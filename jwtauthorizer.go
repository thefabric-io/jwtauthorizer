package jwtauthorizer

type JWTAuthorizer interface {
	ValidateAccessToken(AccessToken) error
}

type AccessToken interface {
	Validate() error
	HasJWKS() bool
	HasScope(scope string) bool
	HasScopes(scopes ...string) bool
}
