package wechat_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/casdoor/casdoor/object"
	"github.com/golang-jwt/jwt/v5"
)

func signedProbeClaims(t *testing.T, app *object.Application, raw string) jwt.MapClaims {
	t.Helper()
	_ = verifiedSubject(t, app, raw)
	cert, err := object.GetCert("admin/cert-built-in")
	if err != nil {
		t.Fatal("signing certificate unavailable")
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cert.Certificate))
	if err != nil {
		t.Fatal("invalid signing certificate")
	}
	token, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return key, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("http://127.0.0.1:8000"),
		jwt.WithAudience(app.ClientId), jwt.WithExpirationRequired())
	if err != nil || token == nil {
		t.Fatal("token trust validation failed")
	}
	return token.Claims.(jwt.MapClaims)
}

func TestWechatCustomClaimsAndFreshBindings(t *testing.T) {
	initializeProbe(t, true)
	owner := fmt.Sprintf("wx-claims-%d", time.Now().UnixNano())
	a := createProbeApplication(t, owner, "a", "claims-a")
	a.TokenFormat = "JWT-Custom"
	a.TokenFields = []string{"Owner", "Type", "DisplayName", "Properties.oauth_WeChat_extra"}
	if _, err := object.UpdateApplication(a.GetId(), a, true, "en", nil); err != nil {
		t.Fatal("custom token configuration update failed")
	}
	var err error
	a, err = object.GetApplication(a.GetId())
	if err != nil || a == nil {
		t.Fatal("custom token application persistence read failed")
	}
	b := createProbeApplication(t, owner, "b", "claims-b")
	original := miniToken(t, a, "new-test-code")
	first := signedProbeClaims(t, a, original.AccessToken)
	if first["tokenType"] != "access-token" || first["owner"] != owner {
		t.Fatal("custom token trust metadata missing")
	}
	for _, key := range []string{"properties", "password", "session_key", "accessToken", "refreshToken"} {
		if _, exists := first[key]; exists {
			t.Fatal("custom token leaked unapproved field")
		}
	}
	extra, ok := first["oauth_WeChat_extra"].(string)
	if !ok {
		t.Fatal("selected WeChat property is not a JSON string")
	}
	var before map[string]string
	if json.Unmarshal([]byte(extra), &before) != nil || before["wechat_openid_claims-a"] != "mini-open" {
		t.Fatal("selected WeChat property did not contain verified application identity")
	}
	other := miniToken(t, b, "new-test-code")
	if verifiedSubject(t, b, other.AccessToken) != verifiedSubject(t, a, original.AccessToken) {
		t.Fatal("second application binding changed subject")
	}
	refreshed, err := refreshProbe(a, original.RefreshToken)
	if err != nil {
		t.Fatal("custom token refresh failed")
	}
	current := signedProbeClaims(t, a, refreshed.AccessToken)
	value, ok := current["oauth_WeChat_extra"].(string)
	var after map[string]string
	if !ok || json.Unmarshal([]byte(value), &after) != nil ||
		after["wechat_openid_claims-a"] != "mini-open" || after["wechat_openid_claims-b"] != "mini-open" {
		t.Fatal("refresh omitted newly verified application binding")
	}
	for key := range after {
		if key != "wechat_unionid" && key != "wechat_openid_claims-a" && key != "wechat_openid_claims-b" {
			t.Fatal("WeChat extra contained an unapproved upstream field")
		}
	}
	idClaims := signedProbeClaims(t, a, refreshed.IdToken)
	refreshClaims := signedProbeClaims(t, a, refreshed.RefreshToken)
	if idClaims["tokenType"] != "id-token" || refreshClaims["tokenType"] != "refresh-token" {
		t.Fatal("token kinds were not distinct")
	}
}
