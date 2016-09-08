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
	ErrAuthentication = errors.New("ErrAuthentication")
	ErrAuthorization  = errors.New("ErrAuthorization")
)

var (
	rsaPrivateKeyCache   = make(map[string]*rsa.PrivateKey)
	rsaPublicKeyCache    = make(map[string]*rsa.PublicKey)
	ecdsaPrivateKeyCache = make(map[string]*ecdsa.PrivateKey)
	ecdsaPublicKeyCache  = make(map[string]*ecdsa.PublicKey)
)

type LoginDataGetter func(r *http.Request) (string, string)
type Authenticator func(string, string) bool
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

type JwtHandler struct {
	SigningMethod   jwt.SigningMethod
	Timeout         time.Duration
	HmacKey         []byte
	RsaPrivateKey   *rsa.PrivateKey
	RsaPublickey    *rsa.PublicKey
	EcdsaPrivateKey *ecdsa.PrivateKey
	EcdsaPublicKey  *ecdsa.PublicKey
	LoginDataGetter LoginDataGetter
	Authenticator   Authenticator
	ErrorHandler    ErrorHandler
}

type Option struct {
	SigningAlgorithm string
	Timeout          time.Duration
	HmacKey          []byte
	PrivateKeyPath   string
	PublicKeyPath    string
	LoginDataGetter  LoginDataGetter
	Authenticator    Authenticator
	ErrorHandler     ErrorHandler
}

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

	// method.Alg() pattern is {HS,RS,PS,ES}{256,384,512}
	switch {
	case h.IsHmac():
		if o.HmacKey == nil {
			return nil, errors.New("hash key must required")
		}
		h.HmacKey = o.HmacKey
	case h.IsRsa():
		if privateKey, ok := rsaPrivateKeyCache[o.PrivateKeyPath]; ok {
			if publicKey, ok := rsaPublicKeyCache[o.PublicKeyPath]; ok {
				h.RsaPrivateKey = privateKey
				h.RsaPublickey = publicKey
			}
		} else {
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
			h.RsaPublickey, e = jwt.ParseRSAPublicKeyFromPEM(publicKeyData)
			if e != nil {
				return nil, errors.New("public key parse error [" + string(o.PublicKeyPath) + "]: " + e.Error())
			}
			rsaPrivateKeyCache[o.PrivateKeyPath] = h.RsaPrivateKey
			rsaPublicKeyCache[o.PublicKeyPath] = h.RsaPublickey
		}
	case h.IsEcdsa():
		if privateKey, ok := ecdsaPrivateKeyCache[o.PrivateKeyPath]; ok {
			if publicKey, ok := ecdsaPublicKeyCache[o.PublicKeyPath]; ok {
				h.EcdsaPrivateKey = privateKey
				h.EcdsaPublicKey = publicKey
			}
		} else {
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

func (h *JwtHandler) IsHmac() bool {
	return h.SigningMethodPrefix() == "HS"
}

func (h *JwtHandler) IsRsa() bool {
	return h.SigningMethodPrefix() == "RS" || h.SigningMethodPrefix() == "PS"
}

func (h *JwtHandler) IsEcdsa() bool {
	return h.SigningMethodPrefix() == "ES"
}

func (h *JwtHandler) SigningMethodPrefix() string {
	return h.SigningMethod.Alg()[0:2]
}

func (h *JwtHandler) AuthenticationHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		username, password := h.LoginDataGetter(r)

		if !h.Authenticator(username, password) {
			h.ErrorHandler(w, r, ErrAuthentication)
			return
		}

		token := jwt.NewWithClaims(h.SigningMethod, jwt.MapClaims{
			"sub": username,
			"exp": time.Now().Add(h.Timeout).Unix(),
		})

		var key interface{}
		switch {
		case h.IsHmac():
			key = h.HmacKey
		case h.IsRsa():
			key = h.RsaPrivateKey
		case h.IsEcdsa():
			key = h.EcdsaPrivateKey
		}

		tokenString, err := token.SignedString(key)
		if err != nil {
			h.ErrorHandler(w, r, err)
		}

		ctx := r.Context()
		r = r.WithContext(context.WithValue(ctx, signedTokenKey, tokenString))

		next.ServeHTTP(w, r)
	})
}

func (h *JwtHandler) AuthorizationHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		token, err := h.parseToken(r)
		if err != nil {
			h.ErrorHandler(w, r, ErrAuthorization)
		}

		if _, ok := token.Claims.(jwt.MapClaims); !ok || !token.Valid {
			h.ErrorHandler(w, r, ErrAuthorization)
		}

		ctx := r.Context()
		r = r.WithContext(context.WithValue(ctx, tokenKey, token))

		next.ServeHTTP(w, r)
	})
}

type key int

var (
	signedTokenKey key = 1
	tokenKey       key = 2
)

func SignedTokenFromContext(ctx context.Context) (string, bool) {
	val, ok := ctx.Value(signedTokenKey).(string)
	return val, ok
}

func TokenFromContext(ctx context.Context) (*jwt.Token, bool) {
	val, ok := ctx.Value(tokenKey).(*jwt.Token)
	return val, ok
}

func readFile(path string) ([]byte, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func loginDataGetter(r *http.Request) (string, string) {
	return r.URL.Query().Get("username"), r.URL.Query().Get("password")
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
		case h.IsHmac():
			return h.HmacKey, nil
		case h.IsRsa():
			return h.RsaPublickey, nil
		case h.IsEcdsa():
			return h.EcdsaPublicKey, nil
		default:
			return nil, errors.New("Invalid signing algorithm")
		}
	})
}
