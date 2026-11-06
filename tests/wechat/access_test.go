package wechat_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/casdoor/casdoor/object"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

func proofKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signedProof(t *testing.T, key *ecdsa.PrivateKey, method, uri, access string) string {
	t.Helper()
	claims := &object.DPoPProofClaims{
		Jti: fmt.Sprint(time.Now().UnixNano()), Htm: method, Htu: uri,
		RegisteredClaims: jwt.RegisteredClaims{IssuedAt: jwt.NewNumericDate(time.Now())},
	}
	if access != "" {
		hash := sha256.Sum256([]byte(access))
		claims.Ath = base64.RawURLEncoding.EncodeToString(hash[:])
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jose.JSONWebKey{Key: &key.PublicKey}
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestWechatPhoneFederatedTokenSources(t *testing.T) {
	initializeProbe(t, true)
	key := proofKey(t)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "test-key", Algorithm: "ES256", Use: "sig"},
		}})
	}))
	defer jwks.Close()
	base := http.DefaultTransport
	calls := &atomic.Int32{}
	http.DefaultTransport = phoneTransport{base, calls, &sync.Map{}}
	t.Cleanup(func() { http.DefaultTransport = base })
	for _, format := range []string{"JWT", "JWT-Empty", "JWT-Standard", "JWT-Custom"} {
		for _, mapped := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/user=%t", format, mapped), func(t *testing.T) {
				app := createProbeApplication(t, fmt.Sprintf("wx-fed-%d", time.Now().UnixNano()), "mini", "fed-mini")
				app.TokenFormat = format
				credential := &object.FederatedCredential{
					Issuer: jwks.URL, JwksUri: jwks.URL,
					Subject: "workload", Audience: app.ClientId,
				}
				user := &object.User{Owner: app.Organization, Name: app.Name, SignupApplication: app.Name}
				if _, err := object.AddUser(user, "en"); err != nil {
					t.Fatal(err)
				}
				if mapped {
					credential.User = user.Name
				}
				app.FederatedCredentials = []*object.FederatedCredential{credential}
				assertion := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
					"iss": jwks.URL, "sub": "workload", "aud": app.ClientId,
					"exp": time.Now().Add(time.Hour).Unix(),
				})
				assertion.Header["kid"] = "test-key"
				raw, err := assertion.SignedString(key)
				if err != nil {
					t.Fatal(err)
				}
				for _, exchange := range []bool{false, true} {
					var token *object.Token
					var tokenError *object.TokenError
					if exchange {
						token, tokenError, err = object.GetTokenExchangeToken(app, app.ClientSecret, raw, "", "", "", "127.0.0.1:8000")
					} else {
						token, tokenError, err = object.GetJwtBearerToken(app, raw, "", "", "127.0.0.1:8000", "127.0.0.1", "en")
					}
					if err != nil || tokenError != nil || token == nil {
						t.Fatalf("formal federated mint: %v / %v", err, tokenError)
					}
					before := calls.Load()
					err = object.BindMemberPhone(app, token.AccessToken, "fed-mini", fmt.Sprintf("%s-%t", app.Name, exchange))
					if mapped && err != nil {
						t.Fatalf("mapped user rejected: %v", err)
					}
					if !mapped && (!errors.Is(err, object.ErrMemberUnauthenticated) || calls.Load() != before) {
						t.Fatalf("federated application authorized a user: %v", err)
					}
					if mapped {
						refreshed, err := object.RefreshToken(app, "refresh_token", token.RefreshToken, "", app.ClientId, app.ClientSecret, "", "127.0.0.1:8000", "", "/api/login/oauth/access_token")
						if err != nil {
							t.Fatal(err)
						}
						wrapper, ok := refreshed.(*object.TokenWrapper)
						if !ok {
							t.Fatalf("refresh failed: %T / %v", refreshed, refreshed)
						}
						if err := object.BindMemberPhone(app, wrapper.AccessToken, "fed-mini", fmt.Sprintf("%s-refresh-%t", app.Name, exchange)); err != nil {
							t.Fatalf("refreshed user rejected: %v", err)
						}
					}
				}
			})
		}
	}
}

func TestWechatPhoneDPoP(t *testing.T) {
	initializeProbe(t, true)
	app := createProbeApplication(t, fmt.Sprintf("wx-dpop-%d", time.Now().UnixNano()), "mini", "dpop-mini")
	initial := miniToken(t, app, "new-test-code")
	key := proofKey(t)
	proof := signedProof(t, key, "POST", object.GetDPoPHtu("127.0.0.1:8000", "/api/login/oauth/access_token"), "")
	result, err := object.RefreshToken(app, "refresh_token", initial.RefreshToken, "", app.ClientId, app.ClientSecret, "", "127.0.0.1:8000", proof, "/api/login/oauth/access_token")
	if err != nil {
		t.Fatal(err)
	}
	token, ok := result.(*object.TokenWrapper)
	if !ok || token.TokenType != "DPoP" {
		t.Fatalf("native DPoP refresh failed: %T / %v", result, result)
	}
	server := phoneServer(t)
	uri := object.GetDPoPHtu(strings.TrimPrefix(server.URL, "http://"), "/api/login/oauth/member-phone")
	base := http.DefaultTransport
	calls := &atomic.Int32{}
	http.DefaultTransport = phoneTransport{base, calls, &sync.Map{}}
	t.Cleanup(func() { http.DefaultTransport = base })
	if err := object.BindMemberPhone(app, token.AccessToken, "dpop-mini", "direct"); !errors.Is(err, object.ErrMemberUnauthenticated) {
		t.Fatalf("direct call bypassed proof: %v", err)
	}
	for _, test := range []struct {
		name, proof string
		status      int
	}{
		{"missing", "", http.StatusUnauthorized},
		{"method", signedProof(t, key, "post", uri, token.AccessToken), http.StatusUnauthorized},
		{"path-case", signedProof(t, key, "POST", strings.Replace(uri, "member-phone", "Member-Phone", 1), token.AccessToken), http.StatusUnauthorized},
		{"escaped-slash", signedProof(t, key, "POST", strings.Replace(uri, "/member-phone", "%2Fmember-phone", 1), token.AccessToken), http.StatusUnauthorized},
		{"key", signedProof(t, proofKey(t), "POST", uri, token.AccessToken), http.StatusUnauthorized},
		{"ath", signedProof(t, key, "POST", uri, "wrong"), http.StatusUnauthorized},
		{"valid", signedProof(t, key, "POST", uri, token.AccessToken), http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := url.Values{"token": {token.AccessToken}, "app_id": {"dpop-mini"}, "code": {test.name}}
			req, err := http.NewRequest("POST", server.URL+"/api/login/oauth/member-phone", strings.NewReader(values.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			req.SetBasicAuth(app.ClientId, app.ClientSecret)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("DPoP", test.proof)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != test.status || (test.status != http.StatusOK && calls.Load() != 0) {
				t.Fatalf("HTTP=%d expected=%d calls=%d", resp.StatusCode, test.status, calls.Load())
			}
		})
	}
}

func TestWechatDPoPURIComponents(t *testing.T) {
	key := proofKey(t)
	for _, test := range []struct {
		proof, request string
		valid          bool
	}{
		{"https://EXAMPLE.com/path?ignored=1", "https://example.com/path", true},
		{"https://example.com/Path", "https://example.com/path", false},
		{"https://example.com/a%2Fb", "https://example.com/a/b", false},
		{"https://example.com/a%2Fb", "https://example.com/a%2Fb", true},
	} {
		_, err := object.ValidateDPoPProof(signedProof(t, key, "POST", test.proof, ""), "POST", test.request, "")
		if (err == nil) != test.valid {
			t.Errorf("URI comparison %s / %s: %v", test.proof, test.request, err)
		}
	}
}
