package util 

import (
	"io/ioutil"
	jwt "github.com/dgrijalva/jwt-go"
	"testing"
)


func TestGenJWT(t *testing.T) {
	keyData, _ := ioutil.ReadFile("test/test_key.pem")
	key, _ := jwt.ParseRSAPrivateKeyFromPEM(keyData)	

	signature := "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidGVzdF9hY2NudCIsInJvbGVzIjpbInJvbGUxIiwicm9sZTIiXSwiZXhwIjoxMjM0LCJpc3MiOiJMb2dpbl9TZXJ2ZXIifQ.hYZ38sZjFUenWVlMlimDxd2z8M1LFTR9zs8_O9RGnxM8n0UJO8GGn12qY2-XrBCv2BLIh2bJXvCee2hDSZO8F9jvKXXMJyYoEtABYrA5MSYm33J1BfcWYsBqKAIFKiTtDrns297OX9nkLyt4_q3J7qUU8EjE6d1Xhc_vqvL-FVjlETwuAqbUBlkRdb_5yNQ03bNzVi7lvIOMEQ4qyOWw3DkudFDGTRQqaHuYT0MgKWU5A_CyEYSOsuIO6ZI77gQyFOrkc2vM1kSo9xPVEoF_34A5w1TWuySJ6c7Sc7JiSOWA5zrTsX6TavvejhfbTeqK5MTfD4AD9wBS_gVeSgdp7Q"
	u := "test_accnt"
	r := []string{"role1", "role2"}

	s, err := GenJWT(u, r, key, 1234)
	if err !=nil {
		t.Errorf("Error: %v", err)
	}

	if signature != s {
		t.Errorf("Got: %s\n Want: %s", s, signature)
	}
}