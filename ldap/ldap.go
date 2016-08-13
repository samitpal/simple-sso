// package ldap is an sso implementation. It uses an ldap backend to authenticate and optionally
// utilize ldap group memberships for setting up roles in the cookie/jwt which can later be used
// by applications for authorization.
package ldap

import (
	"crypto/tls"
	"fmt"
	"gopkg.in/ldap.v2"
	"net/http"
	"time"

	"github.com/samitpal/simple-sso/sso"
	"github.com/samitpal/simple-sso/util"
)

type LdapSSO struct {
	Cookie *sso.CookieConfig
	Ldap   *LdapConfig
}

var (
	ErrUserNotFound = sso.ErrUserNotFound
	ErrUnauthorized = sso.ErrUnAuthorized
)

func NewLdapSSO() (*LdapSSO, error) {
	setupBaseConfig()
	c, err := sso.SetupCookieConfig()
	if err != nil {
		return nil, err
	}

	l := new(LdapConfig)
	err = l.setupLdapConfig()
	if err != nil {
		return nil, err
	}

	return &LdapSSO{c, l}, nil
}

func (ls LdapSSO) Auth(u string, p string) (*string, *[]string, error) {

	ldap.DefaultTimeout = 20 * time.Second // applies to Dial and DialTLS methods.
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ls.Ldap.host, ls.Ldap.port))
	if err != nil {
		return nil, nil, err
	}
	defer l.Close()

	// Reconnect with TLS if sso_ldap_ssl env is set.
	if ls.Ldap.ssl {
		err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil, nil, err
		}
	}

	// First bind with a read only user
	if ls.Ldap.binddn != "" {
		err = l.Bind(ls.Ldap.binddn, ls.Ldap.bindPasswd)
		if err != nil {
			return nil, nil, err
		}
	}

	// Search for the given username
	searchRequestUser := ldap.NewSearchRequest(
		ls.Ldap.basedn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 30, false, // sets a time limit of 30 secs
		fmt.Sprintf("(&(objectClass=inetOrgPerson)(uid=%s))", u),
		[]string{"dn"},
		nil,
	)

	sru, err := l.Search(searchRequestUser)
	if err != nil {
		return nil, nil, err
	}

	if len(sru.Entries) != 1 {
		return nil, nil, ErrUserNotFound
	}

	userdn := sru.Entries[0].DN

	// Bind as the user to verify their password
	err = l.Bind(userdn, p)
	if err != nil {
		return nil, nil, ErrUnauthorized
	}

	// Now find the group membership (if sso_user_roles env is true).
	var g []string
	if BaseConf.UserRoles {
		searchRequestGroups := ldap.NewSearchRequest(
			ls.Ldap.basedn,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 30, false, // sets a time limit of 30 secs
			fmt.Sprintf("(&(objectClass=posixGroup)(memberUid=%s))", u),
			[]string{"cn"},
			nil,
		)
		srg, err := l.Search(searchRequestGroups)
		if err != nil {
			return &u, nil, err
		}

		g = srg.Entries[0].GetAttributeValues("cn")
	}

	return &u, &g, nil
}

func (ls LdapSSO) CTValidHours() int64 {
	return ls.Cookie.ValidHours
}

func (ls LdapSSO) BuildJWTToken(u string, g []string, exp time.Time) (string, error) {
	return util.GenJWT(u, g, PrivateKey, exp.Unix())

}

func (ls LdapSSO) CookieName() string {
	return ls.Cookie.Name
}

func (ls LdapSSO) CookieDomain() string {
	return ls.Cookie.Domain
}

func (ls LdapSSO) BuildCookie(s string, exp time.Time) http.Cookie {
	c := http.Cookie{
		Name:     ls.Cookie.Name,
		Value:    s,
		Domain:   ls.Cookie.Domain,
		Path:     "/",
		Expires:  exp,
		MaxAge:   int(ls.Cookie.ValidHours * 3600),
		Secure:   true,
		HttpOnly: true,
	}
	return c
}

func (ls LdapSSO) Logout(expT time.Time) http.Cookie {
	c := http.Cookie{
		Name:     ls.Cookie.Name,
		Value:    "",
		Domain:   ls.Cookie.Domain,
		Path:     "/",
		Expires:  expT,
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
	}
	return c
}
