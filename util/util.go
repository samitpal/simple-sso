package util

import (
	"crypto/rsa"
	jwt "github.com/dgrijalva/jwt-go"
)

type CustomClaims struct {
	User  string   `json:"user"`
	Roles []string `json:"roles"`
	jwt.StandardClaims
}

// GenJWT generates the jwt token. Among other stuff, it packs in the authenticated user name and the roles that the
// user belongs to and an expiration time. The info is then signed by the private key of the login server.
func GenJWT(u string, g []string, p *rsa.PrivateKey, t int64) (string, error) {
	claims := CustomClaims{
		u,
		g,
		jwt.StandardClaims{
			ExpiresAt: t,
			Issuer:    "Login_Server",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	return token.SignedString(p)
}
