package go_jwt_handler

import (
	"testing"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"log"
	"fmt"
)

func TestJwtHandler_AuthenticationHandler(t *testing.T) {
	hmacKey, _ := ioutil.ReadFile("test/hmacTestKey")
	authenticator := func(username, password string) bool { return username == "admin" && password == "admin" }
	loginDataGetter := func(r *http.Request) (string, string) { return r.URL.Query().Get("user"), r.URL.Query().Get("pass") }

	options := []Option{
		Option{ SigningAlgorithm: "HS256", HmacKey: hmacKey, Authenticator: authenticator, LoginDataGetter: loginDataGetter },
		Option{ SigningAlgorithm: "HS384", HmacKey: hmacKey, Authenticator: authenticator, LoginDataGetter: loginDataGetter },
		Option{ SigningAlgorithm: "HS512", HmacKey: hmacKey, Authenticator: authenticator, LoginDataGetter: loginDataGetter },
		Option{ SigningAlgorithm: "RS256", PrivateKeyPath: "test/sample_key", PublicKeyPath: "test/sample_key.pub", Authenticator: authenticator, LoginDataGetter: loginDataGetter },
		Option{ SigningAlgorithm: "RS384", PrivateKeyPath: "test/sample_key", PublicKeyPath: "test/sample_key.pub", Authenticator: authenticator, LoginDataGetter: loginDataGetter },
		Option{ SigningAlgorithm: "RS512", PrivateKeyPath: "test/sample_key", PublicKeyPath: "test/sample_key.pub", Authenticator: authenticator, LoginDataGetter: loginDataGetter },
		Option{ SigningAlgorithm: "PS256", PrivateKeyPath: "test/sample_key", PublicKeyPath: "test/sample_key.pub", Authenticator: authenticator, LoginDataGetter: loginDataGetter },
		Option{ SigningAlgorithm: "PS384", PrivateKeyPath: "test/sample_key", PublicKeyPath: "test/sample_key.pub", Authenticator: authenticator, LoginDataGetter: loginDataGetter },
		Option{ SigningAlgorithm: "PS512", PrivateKeyPath: "test/sample_key", PublicKeyPath: "test/sample_key.pub", Authenticator: authenticator, LoginDataGetter: loginDataGetter },
		Option{ SigningAlgorithm: "ES256", PrivateKeyPath: "test/ec256-private.pem", PublicKeyPath: "test/ec256-public.pem", Authenticator: authenticator, LoginDataGetter: loginDataGetter },
		Option{ SigningAlgorithm: "ES384", PrivateKeyPath: "test/ec384-private.pem", PublicKeyPath: "test/ec384-public.pem", Authenticator: authenticator, LoginDataGetter: loginDataGetter },
		Option{ SigningAlgorithm: "ES512", PrivateKeyPath: "test/ec512-private.pem", PublicKeyPath: "test/ec512-public.pem", Authenticator: authenticator, LoginDataGetter: loginDataGetter },
	}

	for _, option := range options {
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
		res, err := http.Get(ts.URL + "?user=admin&pass=admin")
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
		res, err = http.Get(ts.URL + "?user=user&pass=user")
		if err != nil {
			t.Fatal(err)
		} else {
			if res.StatusCode != http.StatusUnauthorized {
				t.Fatal("Status must 401")
			}
		}
	}
}
