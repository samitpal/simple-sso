package ldap

import (
	"github.com/samitpal/simple-sso/sso"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func init() {
	os.Setenv(sso.ConfMap["sso_private_key_path"], "../util/test/test_key.pem")
}

func TestBuildCookie(t *testing.T) {
	os.Setenv(sso.ConfMap["sso_cookie_name"], "LoginCookie")
	os.Setenv(sso.ConfMap["sso_cookie_domain"], "test.com")

	ls, err := NewLdapSSO()
	if err != nil {
		t.Errorf("Error: %v", err)
	}

	cv := "Cookie Value"
	expTime := time.Now().Add(time.Hour * time.Duration(ls.CTValidHours()))
	expectedCookie := http.Cookie{
		Name:     ls.CookieName(),
		Value:    cv,
		Domain:   ls.CookieDomain(),
		Path:     "/",
		Expires:  expTime,
		MaxAge:   int(ls.CTValidHours() * 3600),
		Secure:   true,
		HttpOnly: true,
	}
	recCookie := ls.BuildCookie(cv, expTime)
	if !reflect.DeepEqual(expectedCookie, recCookie) {
		t.Errorf("Got %v\n Want: %v", recCookie, expectedCookie)
	}

}

func TestLogout(t *testing.T) {
	os.Setenv(sso.ConfMap["sso_cookie_name"], "LoginCookie")
	os.Setenv(sso.ConfMap["sso_cookie_domain"], "test.com")

	ls, err := NewLdapSSO()
	if err != nil {
		t.Errorf("Error: %v", err)
	}

	expTime := time.Now().Add(time.Hour * time.Duration(-1))
	expectedCookie := http.Cookie{
		Name:     ls.CookieName(),
		Value:    "",
		Domain:   ls.CookieDomain(),
		Path:     "/",
		Expires:  expTime,
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
	}

	recCookie := ls.Logout(expTime)
	if !reflect.DeepEqual(expectedCookie, recCookie) {
		t.Errorf("Got: %v\n Want: %v", recCookie, expectedCookie)
	}
}

func TestCTValidHours(t *testing.T) {
	vh := "30"
	os.Setenv(sso.ConfMap["sso_cookie_validhours"], vh)

	ls, err := NewLdapSSO()
	if err != nil {
		t.Errorf("Error: %v", err)
	}

	i, _ := strconv.Atoi(vh)
	if ls.CTValidHours() != int64(i) {
		t.Errorf("Got: %d\n Want: %d", ls.CTValidHours(), i)
	}
}

func TestCookieName(t *testing.T) {
	cn := "my cookie"
	os.Setenv(sso.ConfMap["sso_cookie_name"], cn)

	ls, err := NewLdapSSO()
	if err != nil {
		t.Errorf("Error: %v", err)
	}

	if ls.CookieName() != cn {
		t.Errorf("Got: %s\n Want: %s", ls.CookieName(), cn)
	}
}

func TestCookieDomain(t *testing.T) {
	dn := "mydomain.com"
	os.Setenv(sso.ConfMap["sso_cookie_domain"], dn)

	ls, err := NewLdapSSO()
	if err != nil {
		t.Errorf("Error: %v", err)
	}

	if ls.CookieDomain() != dn {
		t.Errorf("Got: %s\n Want: %s", ls.CookieDomain(), dn)
	}
}
