package cognito

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/buger/jsonparser"
	"github.com/pascaldekloe/jwt"
	"github.com/thefabric-io/jwtauthorizer"
)

var ErrJWTExpired = errors.New("access token expired")

type AccessToken struct {
	jwt.Claims
	groups    Groups
	tokenUse  string
	scopes    Scopes
	authTime  int64
	version   int64
	clientID  string
	username  string
	rawBearer []byte
}

func (a AccessToken) HasScope(scope string) bool {
	return a.scopes.HasScope(scope)
}

func (a AccessToken) HasScopes(scopes ...string) bool {
	return a.scopes.HasScopes(scopes...)
}

func (a AccessToken) Groups() Groups {
	return a.groups
}

func (a AccessToken) TokenUse() string {
	return a.tokenUse
}

func (a AccessToken) Scopes() Scopes {
	return a.scopes
}

func (a AccessToken) AuthTime() int64 {
	return a.authTime
}

func (a AccessToken) Version() int64 {
	return a.version
}

func (a AccessToken) ClientID() string {
	return a.clientID
}

func (a AccessToken) Username() string {
	return a.username
}

func (a AccessToken) RawBearer() []byte {
	return a.rawBearer
}

func (a AccessToken) String() string {
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
		a.groups.String(),
		a.tokenUse,
		a.scopes.String(),
		time.Unix(a.authTime, 0),
		a.Claims.Issuer,
		a.Claims.Expires.String(),
		a.Claims.Issued.String(),
		a.version,
		a.Claims.ID,
		a.clientID,
		a.username,
		a.rawBearer,
	)
}

func (a AccessToken) Validate() error {
	if !a.Valid(time.Now().UTC()) {
		return ErrJWTExpired
	}
	return nil
}

func (a AccessToken) HasJWKS() bool {
	return true
}

func (a *AccessToken) fromJSON(raw []byte) error {
	_, vt, _, err := jsonparser.Get(raw, "cognito:groups")
	if err != nil {
		if vt != jsonparser.NotExist{
			return err
		}
	}

	if vt != jsonparser.NotExist{
		if vt != jsonparser.Array {
			return fmt.Errorf("cognito group should be array got %s", vt.String())
		}

		_, err = jsonparser.ArrayEach(raw, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
			a.groups.AddValues(string(value))
		}, "cognito:groups")
		if err != nil {
			return err
		}
	}

	if a.tokenUse, err = jsonparser.GetString(raw, "token_use"); err != nil {
		return err
	}

	scopeStr, err := jsonparser.GetString(raw, "scope")
	if err != nil {
		return err
	}

	a.scopes = NewScopes(scopeStr)
	if a.authTime, err = jsonparser.GetInt(raw, "auth_time"); err != nil {
		return err
	}

	if a.version, err = jsonparser.GetInt(raw, "version"); err != nil {
		return err
	}

	a.clientID, err = jsonparser.GetString(raw, "client_id")
	if err != nil {
		return err
	}

	a.username, err = jsonparser.GetString(raw, "username")
	if err != nil {
		return err
	}
	return nil
}

func NewAccessToken(r []byte) (jwtauthorizer.AccessToken, error) {
	at := AccessToken{rawBearer: r}
	claims, err := jwt.ParseWithoutCheck(r)
	if err != nil {
		return nil, err
	}
	at.Claims = *claims
	if err = at.fromJSON(at.Claims.Raw); err != nil {
		return nil, err
	}
	return &at, nil
}

type Scopes struct {
	Values []string
}

func (s Scopes) HasScopes(scopes ...string) bool {
	c := 0
	for _, v := range scopes{
		if s.HasScope(v){
			c++
		}
	}
	if c == len(scopes){
		return true
	}
	return false
}

func (s Scopes) HasScope(scope string) bool {
	for _, v := range s.Values{
		if v == scope{
			return true
		}
	}
	return false
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
