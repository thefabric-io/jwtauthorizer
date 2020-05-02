package cognito

import (
	"errors"
	"fmt"
	"github.com/buger/jsonparser"
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
	AuthTime      int64
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
		time.Unix(a.AuthTime, 0),
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

func (a *accessToken) hydrateFromJSON(raw []byte) error {
	_, vt, _, err := jsonparser.Get(raw, "cognito:groups")
	if err != nil {
		return err
	}
	if vt != jsonparser.Array {
		return errors.New(fmt.Sprintf("cognito group should be array got %s", vt.String()))
	}
	_, err = jsonparser.ArrayEach(raw, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
		a.CognitoGroups.AddValues(string(value))
	}, "cognito:groups")
	if err != nil {
		return err
	}
	if a.TokenUse, err = jsonparser.GetString(raw, "token_use"); err != nil {
		return err
	}
	scopeStr, err := jsonparser.GetString(raw, "scope")
	if err != nil {
		return err
	}
	a.Scopes = NewScopes(scopeStr)
	if a.AuthTime, err = jsonparser.GetInt(raw, "auth_time"); err != nil {
		return err
	}
	if a.Version, err = jsonparser.GetInt(raw, "version"); err != nil {
		return err
	}
	a.ClientID, err = jsonparser.GetString(raw, "client_id")
	if err != nil {
		return err
	}
	a.Username, err = jsonparser.GetString(raw, "username")
	if err != nil {
		return err
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
	if err = at.hydrateFromJSON(at.Claims.Raw); err != nil {
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
