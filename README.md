[![Build Status](https://travis-ci.org/samitpal/simple-sso.svg?branch=master)](https://travis-ci.org/samipal/simple-sso)

[google group](https://groups.google.com/forum/#!forum/simple-sso)

Summary
------------------
simple-sso is an SSO service with support for roles based authorization written in the Go programming language. This has been tested with openldap.

For browser based applications the service exposes the /sso handler which sets the sso cookie for a given domain. The value of the cookie is a
jwt token signed by the rsa private key of the simple-sso service. To use this service the applications need to have the corresponding public key in order to
decrypt the cookie. 

simple-sso also exposes another handler /auth_token which can be used to download the encrypted jwt token. The downloaded token can potentially be
passed as Authorization headers by client applications.

simple-sso also has a form of authorization capabilities. It can optionally pack in the roles (groups) information in the cookie/jwt based on a config environment variables..

They say a picture is thousand times more effective, so here is a diagram which shows traffic flow with simple-sso.

![alt tag](https://docs.google.com/drawings/d/1blQbqjT4lb0nu_lX-WO2OaQPvhg5I2pF0LvPZnQ9ywA/pub?w=960&h=720)

Caveats
------------------
Since time is of essence in this infrastructure, the server time needs to be set and managed correctly.
Communication between this service and the ldap infrastruture should be encrypted.