package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/nirasan/go-jwt-handler"
)

func main() {
	jwth, err := jwthandler.New(jwthandler.Option{
		SigningAlgorithm: "HS256",
		HmacKey:          []byte("MYKEY"),
		Authenticator:    func(u, p string) bool { return u == "admin" && p == "admin" },
		LoginDataGetter:  func(r *http.Request) (string, string) { return r.FormValue("username"), r.FormValue("password") },
	})
	if err != nil {
		log.Fatal(err)
	}
	// plain handler
	http.HandleFunc("/", index)
	// login is authentication handler
	http.Handle("/login", jwth.AuthenticationHandler(http.HandlerFunc(login)))
	// hello is authenticated handler
	http.Handle("/hello", jwth.AuthorizationHandler(http.HandlerFunc(hello)))
	// refresh is authenticated handler
	http.Handle("/refresh", jwth.TokenRefreshHandler(http.HandlerFunc(refresh)))
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `
	<html>
		<head>
			<title>index</title>
		</head>
		<body>
			<form method="post" action="/login">
				<input type="text" name="username" />
				<input type="password" name="password" />
				<input type="submit" value="login" />
			</form>
		</body>
	</html>
	`)
}

// Input: curl -F 'username=admin' -F 'password=admin' http://localhost:8080/login
// Output: Your token is eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0NzM3MzEzNTQsInN1YiI6ImFkbWluIn0.zB6hoNjEHrcYhCx7KD_JdlauqTc08s_cB9IS7w49fyI
func login(w http.ResponseWriter, r *http.Request) {
	token, ok := jwthandler.SignedTokenFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
	fmt.Fprint(w, "Your token is "+token)
}

// Input: curl -H 'Authorization:Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0NzM3MzEzNTQsInN1YiI6ImFkbWluIn0.zB6hoNjEHrcYhCx7KD_JdlauqTc08s_cB9IS7w49fyI' http://localhost:8080/hello
// Output: Your name is admin
func hello(w http.ResponseWriter, r *http.Request) {
	token, ok := jwthandler.TokenFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
	username, ok := jwthandler.SubjectFromToken(token)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
	fmt.Fprint(w, "Your name is "+username)
}

// Input: curl -H 'Authorization:Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0NzM3MzEzNTQsInN1YiI6ImFkbWluIn0.zB6hoNjEHrcYhCx7KD_JdlauqTc08s_cB9IS7w49fyI' http://localhost:8080/refresh
// Output: Your new token is eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0NzM3MzE0MDgsInN1YiI6ImFkbWluIn0.nPpJka3zzUdhVrK-hOV5tRYizmc82cmbfWRvmZNgWGo
func refresh(w http.ResponseWriter, r *http.Request) {
	token, ok := jwthandler.SignedTokenFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
	fmt.Fprint(w, "Your new token is "+token)
}
