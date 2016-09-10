package jwthandler_test

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/nirasan/go-jwt-handler"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
)

func ExampleNew_hmac() {
	h, e := jwthandler.New(jwthandler.Option{
		SigningAlgorithm: "HS256",
		HmacKey:          []byte("KEY_STRING"),
		Authenticator:    func(u, p string) bool { return u == "admin" && p == "pass" },
	})
	if e != nil {
		log.Fatal(e)
	}
	fmt.Printf("%T, %s", h, h.SigningMethod.Alg())
	// Output: *jwthandler.JwtHandler, HS256
}

func ExampleNew_rsa() {
	h, e := jwthandler.New(jwthandler.Option{
		SigningAlgorithm: "RS256",
		PrivateKeyPath:   "test/sample_key",
		PublicKeyPath:    "test/sample_key.pub",
		Authenticator:    func(u, p string) bool { return u == "admin" && p == "pass" },
	})
	if e != nil {
		log.Fatal(e)
	}
	fmt.Printf("%T, %s", h, h.SigningMethod.Alg())
	// Output: *jwthandler.JwtHandler, RS256
}

func ExampleNew_rsapss() {
	h, e := jwthandler.New(jwthandler.Option{
		SigningAlgorithm: "PS256",
		PrivateKeyPath:   "test/sample_key",
		PublicKeyPath:    "test/sample_key.pub",
		Authenticator:    func(u, p string) bool { return u == "admin" && p == "pass" },
	})
	if e != nil {
		log.Fatal(e)
	}
	fmt.Printf("%T, %s", h, h.SigningMethod.Alg())
	// Output: *jwthandler.JwtHandler, PS256
}

func ExampleNew_ecdsa() {
	h, e := jwthandler.New(jwthandler.Option{
		SigningAlgorithm: "ES256",
		PrivateKeyPath:   "test/ec256-private.pem",
		PublicKeyPath:    "test/ec256-public.pem",
		Authenticator:    func(u, p string) bool { return u == "admin" && p == "pass" },
	})
	if e != nil {
		log.Fatal(e)
	}
	fmt.Printf("%T, %s", h, h.SigningMethod.Alg())
	// Output: *jwthandler.JwtHandler, ES256
}

func ExampleJwtHandler_AuthenticationHandler() {
	// create JwtHandler
	jwth, e := jwthandler.New(jwthandler.Option{
		SigningAlgorithm: "HS256",
		HmacKey:          []byte("KEY_STRING"),
		Authenticator: func(u, p string) bool {
			return u == "user" && p == "pass"
		},
		LoginDataGetter: func(r *http.Request) (string, string) {
			return r.FormValue("username"), r.FormValue("password")
		},
	})
	if e != nil {
		log.Fatal(e)
	}

	// create http.Handler
	h := jwth.AuthenticationHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// get signed token string
		token, ok := jwthandler.SignedTokenFromContext(r.Context())

		// and response
		if ok {
			fmt.Fprint(w, token)
		} else {
			http.Error(w, "", http.StatusUnauthorized)
		}
	}))

	// emulate server
	ts := httptest.NewServer(h)
	defer ts.Close()

	// emulate client
	res, _ := http.PostForm(ts.URL, url.Values{"username": {"user"}, "password": {"pass"}})
	body, _ := ioutil.ReadAll(res.Body)
	defer res.Body.Close()

	fmt.Println(res.StatusCode, len(body))
	// Output: 200 123
}

func ExampleJwtHandler_AuthorizationHandler() {
	// create JwtHandler
	jwth, e := jwthandler.New(jwthandler.Option{
		SigningAlgorithm: "HS256",
		HmacKey:          []byte("KEY_STRING"),
		Authenticator: func(u, p string) bool {
			return u == "user" && p == "pass"
		},
		LoginDataGetter: func(r *http.Request) (string, string) {
			return r.FormValue("username"), r.FormValue("password")
		},
	})
	if e != nil {
		log.Fatal(e)
	}

	// create http.Handler
	h := jwth.AuthorizationHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// get token object
		token, ok := jwthandler.TokenFromContext(r.Context())
		if !ok {
			http.Error(w, "", http.StatusUnauthorized)
		}

		// get username
		username, ok := jwthandler.SubjectFromToken(token)

		// reaponse
		fmt.Fprint(w, "Hello "+username)
	}))

	// generate token (normally AuthenticationHander generated)
	username := "user"
	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": username}).SignedString(jwth.HmacKey)

	// emulate server
	ts := httptest.NewServer(h)
	defer ts.Close()

	// emulate client
	client := &http.Client{}
	data := url.Values{"username": {username}, "password": {"pass"}}
	req, _ := http.NewRequest("POST", ts.URL, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	res, _ := client.Do(req)
	body, _ := ioutil.ReadAll(res.Body)
	defer res.Body.Close()

	fmt.Printf("%d %s", res.StatusCode, string(body))
	// Output: 200 Hello user
}

func ExampleJwtHandler_TokenRefreshHandler() {
	// create JwtHandler
	jwth, e := jwthandler.New(jwthandler.Option{
		SigningAlgorithm: "HS256",
		HmacKey:          []byte("KEY_STRING"),
		Authenticator: func(u, p string) bool {
			return u == "user" && p == "pass"
		},
		LoginDataGetter: func(r *http.Request) (string, string) {
			return r.FormValue("username"), r.FormValue("password")
		},
	})
	if e != nil {
		log.Fatal(e)
	}

	// create http.Handler
	h := jwth.TokenRefreshHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// get refreshed token string
		token, ok := jwthandler.SignedTokenFromContext(r.Context())

		// and response
		if ok {
			fmt.Fprint(w, token)
		} else {
			http.Error(w, "", http.StatusUnauthorized)
		}
	}))

	// generate token (normally AuthenticationHander generated)
	username := "user"
	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": username}).SignedString(jwth.HmacKey)

	// emulate server
	ts := httptest.NewServer(h)
	defer ts.Close()

	// emulate client
	client := &http.Client{}
	data := url.Values{"username": {username}, "password": {"pass"}}
	req, _ := http.NewRequest("POST", ts.URL, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	res, _ := client.Do(req)
	body, _ := ioutil.ReadAll(res.Body)
	defer res.Body.Close()

	newToken := string(body)
	if res.StatusCode == 200 && newToken != token {
		fmt.Print("success")
		// Output: success
	}
}