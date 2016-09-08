package jwthandler

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dgrijalva/jwt-go"
)

var (
	authenticator = func(username, password string) bool { return username == "admin" && password == "admin" }
)

func TestJwtHandler_AuthenticationHandler(t *testing.T) {
	hmacKey, _ := ioutil.ReadFile("test/hmacTestKey")

	options := []Option{
		Option{SigningAlgorithm: "HS256", HmacKey: hmacKey, Authenticator: authenticator},
		Option{SigningAlgorithm: "HS384", HmacKey: hmacKey, Authenticator: authenticator},
		Option{SigningAlgorithm: "HS512", HmacKey: hmacKey, Authenticator: authenticator},
		Option{SigningAlgorithm: "RS256", PrivateKeyPath: "test/sample_key", PublicKeyPath: "test/sample_key.pub", Authenticator: authenticator},
		Option{SigningAlgorithm: "RS384", PrivateKeyPath: "test/sample_key", PublicKeyPath: "test/sample_key.pub", Authenticator: authenticator},
		Option{SigningAlgorithm: "RS512", PrivateKeyPath: "test/sample_key", PublicKeyPath: "test/sample_key.pub", Authenticator: authenticator},
		Option{SigningAlgorithm: "PS256", PrivateKeyPath: "test/sample_key", PublicKeyPath: "test/sample_key.pub", Authenticator: authenticator},
		Option{SigningAlgorithm: "PS384", PrivateKeyPath: "test/sample_key", PublicKeyPath: "test/sample_key.pub", Authenticator: authenticator},
		Option{SigningAlgorithm: "PS512", PrivateKeyPath: "test/sample_key", PublicKeyPath: "test/sample_key.pub", Authenticator: authenticator},
		Option{SigningAlgorithm: "ES256", PrivateKeyPath: "test/ec256-private.pem", PublicKeyPath: "test/ec256-public.pem", Authenticator: authenticator},
		Option{SigningAlgorithm: "ES384", PrivateKeyPath: "test/ec384-private.pem", PublicKeyPath: "test/ec384-public.pem", Authenticator: authenticator},
		Option{SigningAlgorithm: "ES512", PrivateKeyPath: "test/ec512-private.pem", PublicKeyPath: "test/ec512-public.pem", Authenticator: authenticator},
	}

	for _, option := range options {
		log.Println(option)

		h, err := New(option)
		if err != nil {
			t.Fatal(err)
		}

		ts := httptest.NewServer(h.AuthenticationHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := SignedTokenFromContext(r.Context())
			if !ok {
				t.Fatal("SignedToken is not exist.")
			}
			fmt.Fprintln(w, token)
		})))
		defer ts.Close()

		// valid username and password
		res, err := http.Get(ts.URL + "?username=admin&password=admin")
		if err != nil {
			t.Fatal(err)
		} else {
			tokenString, err := ioutil.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Fatal(err)
			}

			if len(tokenString) == 0 {
				t.Error("token is empty")
			} else {
				log.Println(string(tokenString))
			}
		}

		// invalid username and password
		res, err = http.Get(ts.URL + "?username=user&password=user")
		if err != nil {
			t.Fatal(err)
		} else {
			if res.StatusCode != http.StatusUnauthorized {
				t.Fatal("Status must 401")
			}
		}

		// invalid parameters
		res, err = http.Get(ts.URL + "?user=admin&pass=admin")
		if err != nil {
			t.Fatal(err)
		} else {
			if res.StatusCode != http.StatusUnauthorized {
				t.Fatal("Status must 401")
			}
		}
	}
}

func TestJwtHandler_AuthorizationHandler(t *testing.T) {
	hmacKey, _ := ioutil.ReadFile("test/hmacTestKey")

	options := []Option{
		Option{SigningAlgorithm: "HS256", HmacKey: hmacKey, Authenticator: authenticator},
		Option{SigningAlgorithm: "HS384", HmacKey: hmacKey, Authenticator: authenticator},
		Option{SigningAlgorithm: "HS512", HmacKey: hmacKey, Authenticator: authenticator},
		Option{SigningAlgorithm: "RS256", PrivateKeyPath: "test/sample_key", PublicKeyPath: "test/sample_key.pub", Authenticator: authenticator},
		Option{SigningAlgorithm: "RS384", PrivateKeyPath: "test/sample_key", PublicKeyPath: "test/sample_key.pub", Authenticator: authenticator},
		Option{SigningAlgorithm: "RS512", PrivateKeyPath: "test/sample_key", PublicKeyPath: "test/sample_key.pub", Authenticator: authenticator},
		Option{SigningAlgorithm: "PS256", PrivateKeyPath: "test/sample_key", PublicKeyPath: "test/sample_key.pub", Authenticator: authenticator},
		Option{SigningAlgorithm: "PS384", PrivateKeyPath: "test/sample_key", PublicKeyPath: "test/sample_key.pub", Authenticator: authenticator},
		Option{SigningAlgorithm: "PS512", PrivateKeyPath: "test/sample_key", PublicKeyPath: "test/sample_key.pub", Authenticator: authenticator},
		Option{SigningAlgorithm: "ES256", PrivateKeyPath: "test/ec256-private.pem", PublicKeyPath: "test/ec256-public.pem", Authenticator: authenticator},
		Option{SigningAlgorithm: "ES384", PrivateKeyPath: "test/ec384-private.pem", PublicKeyPath: "test/ec384-public.pem", Authenticator: authenticator},
		Option{SigningAlgorithm: "ES512", PrivateKeyPath: "test/ec512-private.pem", PublicKeyPath: "test/ec512-public.pem", Authenticator: authenticator},
	}

	for _, option := range options {

		h, err := New(option)
		if err != nil {
			t.Fatal(err)
		}

		ts := httptest.NewServer(h.AuthorizationHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := TokenFromContext(r.Context())
			if !ok {
				t.Fatal("Token is not exist.")
			}
			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				fmt.Fprint(w, claims["sub"])
			}
		})))
		defer ts.Close()

		tokenString, _ := h.createSignedToken(h.createToken("admin"))

		req, _ := http.NewRequest("GET", ts.URL, nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		res, err := new(http.Client).Do(req)
		if err != nil {
			t.Fatal(err)
		} else {
			subject, err := ioutil.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Fatal(err)
			}

			if len(subject) == 0 {
				t.Error("token is empty")
			} else if string(subject) != "admin" {
				t.Error("invalid token")
			} else {
				log.Println(string(subject))
			}
		}
	}
}
