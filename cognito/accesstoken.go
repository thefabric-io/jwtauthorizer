package cognito

import (
	"errors"
	"fmt"
	"github.com/pascaldekloe/jwt"
	"github.com/thefabric-io/jwtauthorizer"
	"strings"
	"time"
)

var ErrJWTExpired = errors.New("access token expired")

type accessToken struct {
	jwt.Claims
	CognitoGroups Groups
	TokenUse      string
	Scopes        Scopes
	AuthTime      jwt.NumericTime
	Version       int64
	ClientID      string
	Username      string
	rawBearer     []byte
}

func (a accessToken) String() string {
	return fmt.Sprintf("\n\nAccessToken\n"+
		"\t|Sub: %s\n"+
		"\t|Groups: %s\n"+
		"\t|TokenUse: %s\n"+
		"\t|Scopes: %s\n"+
		"\t|AuthTime: %s\n"+
		"\t|Iss: %s\n"+
		"\t|Exp: %s\n"+
		"\t|Iat: %s\n"+
		"\t|Version: %d\n"+
		"\t|Jti: %s\n"+
		"\t|ClientID: %s\n"+
		"\t|Username: %s\n"+
		"\t|RawBearer: %s\n",
		a.Claims.Subject,
		a.CognitoGroups.String(),
		a.TokenUse,
		a.Scopes.String(),
		a.AuthTime.Time(),
		a.Claims.Issuer,
		a.Claims.Expires.String(),
		a.Claims.Issued.String(),
		a.Version,
		a.Claims.ID,
		a.ClientID,
		a.Username,
		a.rawBearer,
	)
}

func (a accessToken) Validate() error {
	if !a.Valid(time.Now().UTC()) {
		return ErrJWTExpired
	}
	return nil
}

func (a accessToken) HasJWKS() bool {
	return true
}

func (a *accessToken) unmarshalJSONMap(m map[string]interface{}) error {
	groups, ok := m["cognito:groups"].([]interface{})
	if !ok {
		return fmt.Errorf("want JWT cognito:groups array, got %T", m["cognito:groups"])
	}
	for _, group := range groups {
		s, ok := group.(string)
		if !ok {
			return fmt.Errorf("want JWT cognito:groups strings, got a %T", group)
		}
		a.CognitoGroups.AddValues(s)
	}

	if a.TokenUse, ok = m["token_use"].(string); !ok {
		return fmt.Errorf("want JWT token_use string, got %T", m["token_use"])
	}
	if s, ok := m["scope"].(string); !ok {
		return fmt.Errorf("want JWT scope string, got %T", m["scope"])
	} else {
		a.Scopes = NewScopes(s)
	}
	if f, ok := m["auth_time"].(float64); !ok {
		return fmt.Errorf("want JWT auth_time number, got %T", m["auth_time"])
	} else {
		a.AuthTime = jwt.NumericTime(f)
	}
	if f, ok := m["version"].(float64); ok {
		a.Version = int64(f)
	}
	if a.ClientID, ok = m["client_id"].(string); !ok {
		return fmt.Errorf("want JWT client_id string, got %T", m["client_id"])
	}
	if a.Username, ok = m["username"].(string); !ok {
		return fmt.Errorf("want JWT username string, got %T", m["username"])
	}
	return nil
}

func NewAccessToken(r []byte) (jwtauthorizer.AccessToken, error) {
	at := accessToken{rawBearer: r}
	claims, err := jwt.ParseWithoutCheck(r)
	if err != nil {
		return nil, err
	}
	at.Claims = *claims
	if err = at.unmarshalJSONMap(claims.Set); err != nil {
		return nil, err
	}
	return &at, nil
}

type Scopes struct {
	Values []string
}

func (s Scopes) String() string {
	return fmt.Sprintf("%s", s.Values)
}

func NewScopes(s string) Scopes {
	return Scopes{Values: strings.Split(s, " ")}
}

type Groups struct {
	Values []string
}

func (g Groups) String() string {
	return fmt.Sprintf("%s", g.Values)
}

func (g *Groups) AddValues(vv ...string) {
	g.Values = append(g.Values, vv...)
}
