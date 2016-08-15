[![Build Status](https://travis-ci.org/samitpal/simple-sso.svg?branch=master)](https://travis-ci.org/samitpal/simple-sso)

[google group](https://groups.google.com/forum/#!forum/simple-sso)

Summary
------------------
simple-sso is an SSO service with support for roles based authorization written in the Go programming language. 

For browser based applications the service exposes the /sso handler which sets the sso cookie for a given domain. For instance if the login service runs as login.example.com, the sso cookie domain could be configured as example.com. That way any application running under a subdomain of example.com will be able to leverage the sso service (see [rfc6265](https://tools.ietf.org/html/rfc6265#page-6)). The value of the sso cookie is a [jwt](https://jwt.io/) token signed by the rsa private key of the simple-sso service. To use this service the application needs to have the corresponding public key in order to decrypt the cookie. The app checks for the presence of the sso cookie and in the absence of that it redirects to the /sso handler of the sample-sso service setting the **s_url** parameter to its url. The login service is expected to redirect the user back to **s_url** post authentication. See the code under example_app directory.

simple-sso exposes /auth_token handler which can be used to download the encrypted jwt token. The downloaded token can potentially be passed via Authorization headers by client applications to server apps hopefully using ssl.

simple-sso also has a form of authorization capabilities. It can optionally pack in the roles (e.g openldap groups) information in the cookie/jwt based on a config environment variables..

They say a picture is thousand times more effective, so here is a diagram which shows traffic flow with simple-sso.

![alt tag](https://docs.google.com/drawings/d/1blQbqjT4lb0nu_lX-WO2OaQPvhg5I2pF0LvPZnQ9ywA/pub?w=960&h=720)

Installation
-------------------
##### To build from source follow the steps below: 

```sh
$ go get -u github.com/jteeuwen/go-bindata/...

$ go get -u github.com/samitpal/simple-sso/...

$ export PATH=$PATH:$GOPATH/bin

$ go generate

$ go install
```

Running the binary
-------------------

Just run the simple-sso binary. Following principles of 12 factor app, simple-sso uses environment variables for its configurations. These are.

| Variable      | Default value | Purpose |
|---------------|--------------|------------|
| sso_ssl_cert_path  |  ssl_certs/cert.pem | ssl certificate path. |
| sso_ssl_key_path  |ssl_certs/key.pem   | ssl certificate private key. |
| sso_private_key_path  | key_pair/demo.rsa  | rsa private key path used to sign the token. |
| sso_weblog_dir  |  - | Directory path where access hits are logged. |
| sso_user_roles  | false  | Whether to pack in the roles info within the token. |
| sso_cookie_name  | SSO_C  | Name of the sso cookie. |
| sso_cookie_domain  | 127.0.0.1  | Domain name of the cookie. |
| sso_cookie_validhours  | 20  | Cookie validity in hours. |
| sso_ldap_host  | localhost  | Ldap host. |
| sso_ldap_port  | 389  | Ldap host port. |
| sso_ldap_ssl  | false  | whether to use ssl. |
| sso_ldap_basedn  | - | Ldap base dn. |
| sso_ldap_binddn  | - | Ldap bind dn if anonymous bind is disallowed. |
| sso_ldap_bindpasswd  | - | Ldap bind password if anonymous bind is disallowed. |


Caveats
------------------
* Since time is of essence in this infrastructure, the server time needs to be set and managed correctly.
* Communication between this service and the ldap infrastruture should be encrypted.
* This has been tested with openldap.