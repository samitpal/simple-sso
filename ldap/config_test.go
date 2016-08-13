package ldap

import (
	"github.com/samitpal/simple-sso/sso"
	"os"
	"reflect"
	"testing"
)

func TestSetupDefaultString(t *testing.T) {
	s := "return_me"
	d := "not_me"
	r := setDefaultString(s, d)
	if r != s {
		t.Errorf("Got: %s Want: %s", r, s)
	}

	s1 := ""
	d1 := "return_me"
	r = setDefaultString(s1, d1)
	if r != d1 {
		t.Errorf("Got: %s Want: %s", r, d1)
	}
}

func TestSetupLdapConfig(t *testing.T) {
	os.Setenv(sso.ConfMap["sso_ldap_host"], "host")
	os.Setenv(sso.ConfMap["sso_ldap_port"], "123")
	os.Setenv(sso.ConfMap["sso_ldap_ssl"], "true")
	os.Setenv(sso.ConfMap["sso_ldap_basedn"], "basedn")
	os.Setenv(sso.ConfMap["sso_ldap_binddn"], "binddn")
	os.Setenv(sso.ConfMap["sso_ldap_bindpasswd"], "bindpasswd")
	l := LdapConfig{}
	err := l.setupLdapConfig()
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	w := LdapConfig{"host", 123, true, "basedn", "binddn", "bindpasswd"}
	if !reflect.DeepEqual(l, w) {
		t.Errorf("Got: %v\n \tWant: %v", l, w)
	}

	_ = os.Unsetenv(sso.ConfMap["sso_ldap_host"])
	_ = os.Unsetenv(sso.ConfMap["sso_ldap_port"])
	_ = os.Unsetenv(sso.ConfMap["sso_ldap_ssl"])
	err = l.setupLdapConfig()
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	w = LdapConfig{"localhost", 389, false, "basedn", "binddn", "bindpasswd"}
	if !reflect.DeepEqual(l, w) {
		t.Errorf("Got: %v\n \tWant: %v", l, w)
	}

}
