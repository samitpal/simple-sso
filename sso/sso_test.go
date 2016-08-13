package sso

import (
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

func TestSetupBaseConfig(t *testing.T) {
	expBaseConfig := BaseConfig{
		"ssl_certs/cert.pem",
		"ssl_certs/key.pem",
		"key_pair/demo.rsa",
		"",
		false,
	}
	b, err := SetupBaseConfig()
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(expBaseConfig, *b) {
		t.Errorf("Got: %v\n\t Want: %v", *b, expBaseConfig)
	}

	expBaseConfig = BaseConfig{
		"ssl_certs/certreal.pem",
		"ssl_certs/keyreal.pem",
		"key_pair/privatereal.rsa",
		"/tmp/weblog",
		true,
	}

	os.Setenv(ConfMap["sso_ssl_cert_path"], "ssl_certs/certreal.pem")
	os.Setenv(ConfMap["sso_ssl_key_path"], "ssl_certs/keyreal.pem")
	os.Setenv(ConfMap["sso_private_key_path"], "key_pair/privatereal.rsa")
	os.Setenv(ConfMap["sso_weblog_dir"], "/tmp/weblog")
	os.Setenv(ConfMap["sso_user_roles"], "true")
	b, err = SetupBaseConfig()
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(expBaseConfig, *b) {
		t.Errorf("Got: %v\n\t Want: %v", *b, expBaseConfig)
	}
}

func TestSetupCookieConfig(t *testing.T) {
	expCookie := CookieConfig{
		"SSO_C",
		"127.0.0.1",
		20,
	}

	c, err := SetupCookieConfig()
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(expCookie, *c) {
		t.Errorf("Got: %v\n Want: %v", *c, expCookie)
	}

	expCookie = CookieConfig{
		"Cookie",
		"abc.com",
		10,
	}
	os.Setenv((ConfMap["sso_cookie_name"]), "Cookie")
	os.Setenv((ConfMap["sso_cookie_domain"]), "abc.com")
	os.Setenv((ConfMap["sso_cookie_validhours"]), "10")
	c, err = SetupCookieConfig()
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(expCookie, *c) {
		t.Errorf("Got: %v\n Want: %v", *c, expCookie)
	}

}
