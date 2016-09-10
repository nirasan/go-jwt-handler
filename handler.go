package jwthandler

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var (
	// ErrAuthentication is Error for Authentication failed.
	ErrAuthentication = errors.New("Authentication Error")
	// ErrAuthorization is Error for Authorization failed.
	ErrAuthorization = errors.New("Authorization Error")
)

var (
	rsaPrivateKeyCache   = make(map[string]*rsa.PrivateKey)
	rsaPublicKeyCache    = make(map[string]*rsa.PublicKey)
	ecdsaPrivateKeyCache = make(map[string]*ecdsa.PrivateKey)
	ecdsaPublicKeyCache  = make(map[string]*ecdsa.PublicKey)
)

// LoginDataGetter is user defined function getting username and password
type LoginDataGetter func(r *http.Request) (string, string)

// Authenticator is user defined function validating username and password
type Authenticator func(string, string) bool

// ErrorHandler is user defined function handling response when error occurred
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

// JwtHandler is JSON Web Token handler
type JwtHandler struct {
	SigningMethod   jwt.SigningMethod
	Timeout         time.Duration
	HmacKey         []byte
	RsaPrivateKey   *rsa.PrivateKey
	RsaPublicKey    *rsa.PublicKey
	EcdsaPrivateKey *ecdsa.PrivateKey
	EcdsaPublicKey  *ecdsa.PublicKey
	LoginDataGetter LoginDataGetter
	Authenticator   Authenticator
	ErrorHandler    ErrorHandler
}

// Option is JwtHandler constructor option
type Option struct {
	// signing algorithm.
	// possible values are HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512.
	SigningAlgorithm string
	// Duration that a jwt token is valid. Optional, defaults to one hour.
	Timeout time.Duration
	// key for HMAC SHA algorithm.
	HmacKey []byte
	// private key file path for RSA, RSA-PSS, ECDSA algorithm.
	PrivateKeyPath string
	// public key file path for RSA, RSA-PSS, ECDSA algorithm.
	PublicKeyPath string
	// callback function username and password getter.
	LoginDataGetter LoginDataGetter
	// callback function username and password validator.
	// return true if username and password is valid, and return false if invalid.
	Authenticator Authenticator
	// callback function when error occurred handler.
	ErrorHandler ErrorHandler
}

// New is JwtHandler Constructor.
func New(o Option) (*JwtHandler, error) {

	method := jwt.GetSigningMethod(o.SigningAlgorithm)
	if method == nil {
		return nil, errors.New("invalid signing algorithm")
	}

	if o.Authenticator == nil {
		return nil, errors.New("Authenticator required")
	}

	h := &JwtHandler{
		SigningMethod:   method,
		Timeout:         o.Timeout,
		ErrorHandler:    o.ErrorHandler,
		LoginDataGetter: o.LoginDataGetter,
		Authenticator:   o.Authenticator,
	}

	if h.LoginDataGetter == nil {
		h.LoginDataGetter = loginDataGetter
	}

	if h.ErrorHandler == nil {
		h.ErrorHandler = errorHandler
	}

	if h.Timeout == 0 {
		h.Timeout = time.Hour * 1
	}

	switch {
	case h.isHmac():
		if o.HmacKey == nil {
			return nil, errors.New("hash key required")
		}
		h.HmacKey = o.HmacKey
	case h.isRsa():
		if privateKey, ok := rsaPrivateKeyCache[o.PrivateKeyPath]; ok {
			if publicKey, ok := rsaPublicKeyCache[o.PublicKeyPath]; ok {
				h.RsaPrivateKey = privateKey
				h.RsaPublicKey = publicKey
			}
		}
		if h.RsaPrivateKey == nil || h.RsaPublicKey == nil {
			if o.PrivateKeyPath == "" {
				return nil, errors.New("private key path required")
			}
			if o.PublicKeyPath == "" {
				return nil, errors.New("public key path required")
			}
			privateKeyData, e := readFile(o.PrivateKeyPath)
			if e != nil {
				return nil, errors.New("private key read error [" + o.PrivateKeyPath + "]: " + e.Error())
			}
			publicKeyData, e := readFile(o.PublicKeyPath)
			if e != nil {
				return nil, errors.New("public key read error [" + o.PrivateKeyPath + "]: " + e.Error())
			}
			h.RsaPrivateKey, e = jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)
			if e != nil {
				return nil, errors.New("private key parse error [" + string(o.PrivateKeyPath) + "]: " + e.Error())
			}
			h.RsaPublicKey, e = jwt.ParseRSAPublicKeyFromPEM(publicKeyData)
			if e != nil {
				return nil, errors.New("public key parse error [" + string(o.PublicKeyPath) + "]: " + e.Error())
			}
			rsaPrivateKeyCache[o.PrivateKeyPath] = h.RsaPrivateKey
			rsaPublicKeyCache[o.PublicKeyPath] = h.RsaPublicKey
		}
	case h.isEcdsa():
		if privateKey, ok := ecdsaPrivateKeyCache[o.PrivateKeyPath]; ok {
			if publicKey, ok := ecdsaPublicKeyCache[o.PublicKeyPath]; ok {
				h.EcdsaPrivateKey = privateKey
				h.EcdsaPublicKey = publicKey
			}
		}
		if h.EcdsaPrivateKey == nil || h.EcdsaPublicKey == nil {
			if o.PrivateKeyPath == "" {
				return nil, errors.New("private key path required")
			}
			if o.PublicKeyPath == "" {
				return nil, errors.New("public key path required")
			}
			privateKeyData, e := readFile(o.PrivateKeyPath)
			if e != nil {
				return nil, errors.New("private key read error [" + o.PrivateKeyPath + "]: " + e.Error())
			}
			publicKeyData, e := readFile(o.PublicKeyPath)
			if e != nil {
				return nil, errors.New("public key read error [" + o.PrivateKeyPath + "]: " + e.Error())
			}
			h.EcdsaPrivateKey, e = jwt.ParseECPrivateKeyFromPEM(privateKeyData)
			if e != nil {
				return nil, errors.New("private key parse error [" + string(o.PrivateKeyPath) + "]: " + e.Error())
			}
			h.EcdsaPublicKey, e = jwt.ParseECPublicKeyFromPEM(publicKeyData)
			if e != nil {
				return nil, errors.New("public key parse error [" + string(o.PublicKeyPath) + "]: " + e.Error())
			}
			ecdsaPrivateKeyCache[o.PrivateKeyPath] = h.EcdsaPrivateKey
			ecdsaPublicKeyCache[o.PublicKeyPath] = h.EcdsaPublicKey
		}
	default:
		return nil, errors.New("invalid method: " + method.Alg())
	}

	return h, nil
}

// CacheClear can be used by clients to clear key cache
func CacheClear() {
	rsaPrivateKeyCache = make(map[string]*rsa.PrivateKey)
	rsaPublicKeyCache = make(map[string]*rsa.PublicKey)
	ecdsaPrivateKeyCache = make(map[string]*ecdsa.PrivateKey)
	ecdsaPublicKeyCache = make(map[string]*ecdsa.PublicKey)
}

// isHmac decide algorithm is HMAC SHA or not.
func (h *JwtHandler) isHmac() bool {
	return h.signingMethodPrefix() == "HS"
}

// isRsa decide algorithm is (RSA || RSA-PSS) or not.
func (h *JwtHandler) isRsa() bool {
	return h.signingMethodPrefix() == "RS" || h.signingMethodPrefix() == "PS"
}

// isEcdsa decide algorithm is ECDSA or not.
func (h *JwtHandler) isEcdsa() bool {
	return h.signingMethodPrefix() == "ES"
}

func (h *JwtHandler) signingMethodPrefix() string {
	return h.SigningMethod.Alg()[0:2]
}

// AuthenticationHandler can be used by clients to authentication and get token.
// Clients must define the username and password getter and the authenticator.
// On success, token is stored in http.Request.Context.
func (h *JwtHandler) AuthenticationHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		username, password := h.LoginDataGetter(r)

		if !h.Authenticator(username, password) {
			h.ErrorHandler(w, r, ErrAuthentication)
			return
		}

		tokenString, err := h.createSignedToken(h.createToken(username))
		if err != nil {
			h.ErrorHandler(w, r, err)
			return
		}

		ctx := r.Context()
		r = r.WithContext(context.WithValue(ctx, signedTokenKey, tokenString))

		next.ServeHTTP(w, r)
	})
}

// AuthorizationHandler can be used by clients to authorization token.
// Clients must set the token to Authorization header. Example: "Authorization:Bearer {SIGNED_TOKEN_STRING}"
// On succss, token is stored in http.Request.Context.
func (h *JwtHandler) AuthorizationHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		token, err := h.parseToken(r)
		if err != nil {
			h.ErrorHandler(w, r, ErrAuthorization)
			return
		}

		if _, ok := token.Claims.(jwt.MapClaims); !ok || !token.Valid {
			h.ErrorHandler(w, r, ErrAuthorization)
			return
		}

		ctx := r.Context()
		r = r.WithContext(context.WithValue(ctx, tokenKey, token))

		next.ServeHTTP(w, r)
	})
}

// TokenRefreshHandler can be used by clients to refresh token expire time.
// On success, new token is signed token string is stored in http.Request.Context.
func (h *JwtHandler) TokenRefreshHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		token, err := h.parseToken(r)

		if err != nil {
			h.ErrorHandler(w, r, ErrAuthorization)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			h.ErrorHandler(w, r, ErrAuthorization)
			return
		}

		sub := claims["sub"].(string)

		newToken := h.createToken(sub)
		tokenString, err := h.createSignedToken(newToken)
		if err != nil {
			h.ErrorHandler(w, r, err)
			return
		}

		ctx := r.Context()
		r = r.WithContext(context.WithValue(ctx, signedTokenKey, tokenString))

		next.ServeHTTP(w, r)
	})
}

type key int

var (
	signedTokenKey key = 1
	tokenKey       key = 2
)

// SignedTokenFromContext is signed token string getter from http.Request.Context.
func SignedTokenFromContext(ctx context.Context) (string, bool) {
	val, ok := ctx.Value(signedTokenKey).(string)
	return val, ok
}

// TokenFromContext is token instance getter from http.Request.Context.
func TokenFromContext(ctx context.Context) (*jwt.Token, bool) {
	val, ok := ctx.Value(tokenKey).(*jwt.Token)
	return val, ok
}

// SubjectFromToken returns claims subject
func SubjectFromToken(token *jwt.Token) (string, bool) {
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims["sub"].(string), true
	}
	return "", false
}

func readFile(path string) ([]byte, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func loginDataGetter(r *http.Request) (string, string) {
	q := r.URL.Query()
	return q.Get("username"), q.Get("password")
}

func (h *JwtHandler) createToken(username string) *jwt.Token {

	return jwt.NewWithClaims(h.SigningMethod, jwt.MapClaims{
		"sub": username,
		"exp": time.Now().Add(h.Timeout).Unix(),
	})
}

func (h *JwtHandler) createSignedToken(token *jwt.Token) (string, error) {

	var key interface{}
	switch {
	case h.isHmac():
		key = h.HmacKey
	case h.isRsa():
		key = h.RsaPrivateKey
	case h.isEcdsa():
		key = h.EcdsaPrivateKey
	}

	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", err
	}

	return tokenString, err
}

func errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, err.Error(), http.StatusUnauthorized)
}

func (h *JwtHandler) parseToken(r *http.Request) (*jwt.Token, error) {
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		return nil, errors.New("Auth header empty")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == "Bearer") {
		return nil, errors.New("Invalid auth header")
	}

	return jwt.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
		if h.SigningMethod != token.Method {
			return nil, errors.New("Invalid signing algorithm")
		}
		switch {
		case h.isHmac():
			return h.HmacKey, nil
		case h.isRsa():
			return h.RsaPublicKey, nil
		case h.isEcdsa():
			return h.EcdsaPublicKey, nil
		default:
			return nil, errors.New("Invalid signing algorithm")
		}
	})
}
