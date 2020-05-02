package cognito

type AuthorizedIssuers []string

func (ai *AuthorizedIssuers) AddAuthorizedIssuers(ii ...string) {
	*ai = append(*ai, ii...)
}

func (ai AuthorizedIssuers) IssuerIsAuthorized(iss string) bool {
	for _, v := range ai {
		if iss == v {
			return true
		}
	}
	return false
}
