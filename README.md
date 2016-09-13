# Go JSON Web Token Handler
This is a http.Handler for authentication and authorization using JWT (JSON Web Token).

## Dependences
* Go 1.7 or higher
* github.com/dgrijalva/jwt-go

## Install
```sh
go get github.com/dgrijalva/jwt-go
go get github.com/nirasan/go-jwt-handler
```

## Features
* Multi signing algorithm (HMAC SHA, RSA, RSA PSS, ECDSA).
* Authentication and authorization and token refresh http.Handler
* Delivery signed token and authenticated token to clients using http.Request.Context.

## Example
