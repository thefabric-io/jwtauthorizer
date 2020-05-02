package cognito

import (
	"errors"
	"github.com/pascaldekloe/jwt"
	"github.com/thefabric-io/jwtauthorizer"
	"io/ioutil"
	"net/http"
)

var ErrIssuerNotFound = errors.New("issuer not found")
var ErrKeyRegisterNotFound = errors.New("key register not found")
var ErrIssuerNotAuthorized = errors.New("issuer not authorized")

func NewAuthService(ai AuthorizedIssuers) (jwtauthorizer.JWTAuthorizer, error){
	if len(ai) == 0{
		return nil, errors.New("authorised issuers cannot be empty")
	}
	as := authService{
		authorizedIssuers: ai,
	}
	if err := as.initJwks(); err != nil{
		return nil, err
	}
	return &as, nil
}

type authService struct {
	authorizedIssuers AuthorizedIssuers
	keyRegister       map[string]jwt.KeyRegister
}

func (s *authService) initJwks() error{
	s.keyRegister = make(map[string]jwt.KeyRegister,len(s.authorizedIssuers))
	for _, v := range s.authorizedIssuers{
		b, err := fetchJwks(v)
		jwks := jwt.KeyRegister{}
		_, err = jwks.LoadJWK(b)
		if err != nil {
			return err
		}
		s.keyRegister[v] = jwks
	}
	return nil
}

func (s authService) KeyRegister(iss string) (*jwt.KeyRegister, error){
	kr, ok := s.keyRegister[iss]
	if !ok{
		return nil, ErrKeyRegisterNotFound
	}
	return &kr, nil
}

func (s authService) ValidateAccessToken(token jwtauthorizer.AccessToken) error{
	a := token.(*accessToken)
	if !s.authorizedIssuers.IssuerIsAuthorized(a.Issuer){
		return ErrIssuerNotAuthorized
	}
	if err := a.Validate(); err != nil{
		return err
	}
	if a.HasJWKS(){
		jwks, err := s.KeyRegister(a.Issuer)
		if err != nil {
			return err
		}
		if _, err = jwks.Check(a.rawBearer); err != nil{
			return err
		}
	}
	return nil
}

func fetchJwks(v string) ([]byte, error){
	res, err := http.Get(v+"/.well-known/jwks.json")
	if err != nil{
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK{
		return nil, ErrIssuerNotFound
	}
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return b, nil
}