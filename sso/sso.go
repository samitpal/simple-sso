package sso

import (
	"errors"
	"net/http"
	"os"
	"strconv"
	"time"
)

var (
	ErrUnAuthorized = errors.New("Not Authorized")
	ErrUserNotFound = errors.New("User Not Found")
)

// SSOImplementer is what it needs to be implemented for sso functionality.
type SSOer interface {
	// Auth takes user,password strings as arguments and returns the user, user roles (e.g ldap groups)
	// (string slice) if the call succeds. Auth should return the ErrUnAuthorized or ErrUserNotFound error if
	// auth fails or if the user is not found respectively.
	Auth(string, string) (*string, *[]string, error)
	// CTValidHours returns the cookie/jwt token validity in hours.
	CTValidHours() int64
	CookieName() string
	CookieDomain() string
	// BuildJWTToken takes the user and the user roles info which is then signed by the private
	// key of the login server. The expiry of the token is set per the third argument.
	BuildJWTToken(string, []string, time.Time) (string, error)
	// BuildCookie takes the jwt token and returns a cookie and sets the expiration time of the same to that of
	// the second arg.
	BuildCookie(string, time.Time) http.Cookie
	// Logout sets the expiration time of the cookie in the past rendering it unusable.
	Logout(time.Time) http.Cookie
}

var Err401Map = map[error]bool{
	ErrUnAuthorized: true,
	ErrUserNotFound: true,
}

// All environment variables config goes here for better tracking.
var ConfMap = map[string]string{
	// ssl certs.
	"sso_ssl_cert_path": "sso_ssl_cert_path",
	"sso_ssl_key_path":  "sso_ssl_key_path",
	// private key path for signing the jwt.
	"sso_private_key_path": "sso_private_key_path",
	// weblog dir path
	"sso_weblog_dir": "sso_weblog_dir",
	// User roles for authorization, (true/false)
	"sso_user_roles": "sso_user_roles",
	// cookie configs.
	"sso_cookie_name":       "sso_cookie_name",
	"sso_cookie_domain":     "sso_cookie_domain",
	"sso_cookie_validhours": "sso_cookie_validhours",
	// ldap configs. This should go into the respective package.
	"sso_ldap_host":       "sso_ldap_host",
	"sso_ldap_port":       "sso_ldap_port",
	"sso_ldap_ssl":        "sso_ldap_ssl",
	"sso_ldap_basedn":     "sso_ldap_basedn",
	"sso_ldap_binddn":     "sso_ldap_binddn",
	"sso_ldap_bindpasswd": "sso_ldap_bindpasswd",
}

// setDefaultString returns a given default string.
func setDefaultString(s string, d string) string {
	if s == "" {
		return d
	}
	return s
}

type BaseConfig struct {
	SSLCertPath    string
	SSLKeyPath     string
	PrivateKeyPath string
	WeblogDir      string
	UserRoles      bool
}

// SetupBaseConfig function setups some generic configs
func SetupBaseConfig() (*BaseConfig, error) {
	sslCertPath := setDefaultString(os.Getenv(ConfMap["sso_ssl_cert_path"]), "ssl_certs/cert.pem")
	sslKeyPath := setDefaultString(os.Getenv(ConfMap["sso_ssl_key_path"]), "ssl_certs/key.pem")
	privateKeyPath := setDefaultString(os.Getenv(ConfMap["sso_private_key_path"]), "key_pair/demo.rsa")
	weblogDir := setDefaultString(os.Getenv(ConfMap["sso_weblog_dir"]), "")
	userRoles, err := strconv.ParseBool(setDefaultString(os.Getenv(ConfMap["sso_user_roles"]), "false"))
	if err != nil {
		return nil, err
	}
	return &BaseConfig{sslCertPath, sslKeyPath, privateKeyPath, weblogDir, userRoles}, nil
}

type CookieConfig struct {
	Name       string
	Domain     string
	ValidHours int64
}

// SetupCookieConfig sets up cookie config.
func SetupCookieConfig() (*CookieConfig, error) {
	name := setDefaultString(os.Getenv(ConfMap["sso_cookie_name"]), "SSO_C")
	domain := setDefaultString(os.Getenv(ConfMap["sso_cookie_domain"]), "127.0.0.1")
	validHours, err := strconv.Atoi(setDefaultString(os.Getenv(ConfMap["sso_cookie_validhours"]), "20"))
	if err != nil {
		return nil, err
	}
	return &CookieConfig{name, domain, int64(validHours)}, nil
}
