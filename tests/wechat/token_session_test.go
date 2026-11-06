package wechat_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/controllers"
	"github.com/casdoor/casdoor/object"
)

func refreshProbe(app *object.Application, raw string) (*object.TokenWrapper, error) {
	result, err := object.RefreshToken(app, "refresh_token", raw, "", app.ClientId,
		app.ClientSecret, "", "127.0.0.1:8000", "", "")
	if err != nil {
		return nil, err
	}
	switch value := result.(type) {
	case *object.TokenWrapper:
		return value, nil
	case *object.TokenError:
		return nil, fmt.Errorf("refresh rejected: %s", value.Error)
	default:
		return nil, fmt.Errorf("unexpected refresh response")
	}
}

func oauthRequest(t *testing.T, server string, app *object.Application, path, raw, hint string) (int, []byte) {
	t.Helper()
	form := url.Values{"token": {raw}, "token_type_hint": {hint}}
	req, err := http.NewRequest(http.MethodPost, server+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(app.ClientId, app.ClientSecret)
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal("OAuth request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal("OAuth response read failed")
	}
	return response.StatusCode, body
}

func introspectionActive(t *testing.T, server string, app *object.Application, raw string) bool {
	t.Helper()
	status, body := oauthRequest(t, server, app, "/api/login/oauth/introspect", raw, "access_token")
	var response struct{ Active bool }
	if status != http.StatusOK || json.Unmarshal(body, &response) != nil {
		t.Fatalf("introspection failed: status=%d", status)
	}
	return response.Active
}

func TestWechatApplicationRevocation(t *testing.T) {
	initializeProbe(t, true)
	web.Router("/api/login/oauth/introspect", &controllers.ApiController{}, "POST:IntrospectToken")
	web.Router("/api/login/oauth/revoke", &controllers.ApiController{}, "POST:RevokeToken")
	server := httptest.NewServer(web.BeeApp.Handlers)
	defer server.Close()
	owner := fmt.Sprintf("wx-revoke-%d", time.Now().UnixNano())
	a := createProbeApplication(t, owner, "a", "revoke-a")
	b := createProbeApplication(t, owner, "b", "revoke-b")
	original := miniToken(t, a, "new-test-code")
	other := miniToken(t, b, "new-test-code")
	successor, err := refreshProbe(a, original.RefreshToken)
	if err != nil {
		t.Fatal("initial refresh failed")
	}
	parent, err := object.GetTokenByAccessToken(original.AccessToken)
	if err != nil || parent != nil {
		t.Fatal("native rotation must delete the parent token")
	}
	if _, err := refreshProbe(a, original.RefreshToken); err == nil {
		t.Fatal("deleted parent refresh accepted")
	}
	if !introspectionActive(t, server.URL, a, successor.AccessToken) ||
		!introspectionActive(t, server.URL, b, other.AccessToken) {
		t.Fatal("fresh sessions were inactive")
	}
	for i := 0; i < 2; i++ {
		status, _ := oauthRequest(t, server.URL, a, "/api/login/oauth/revoke", original.RefreshToken, "refresh_token")
		if status != http.StatusOK {
			t.Fatalf("application revocation endpoint failed: status=%d", status)
		}
		if !introspectionActive(t, server.URL, a, successor.AccessToken) {
			t.Fatal("revoking a deleted parent invalidated the successor")
		}
		if !introspectionActive(t, server.URL, b, other.AccessToken) {
			t.Fatal("application logout revoked another application")
		}
	}
	status, _ := oauthRequest(t, server.URL, a, "/api/login/oauth/revoke", successor.RefreshToken, "refresh_token")
	if status != http.StatusOK || introspectionActive(t, server.URL, a, successor.AccessToken) {
		t.Fatal("revoking the current token did not invalidate it")
	}
	if _, err := refreshProbe(a, successor.RefreshToken); err == nil {
		t.Fatal("revoked successor refresh accepted")
	}
	status, _ = oauthRequest(t, server.URL, a, "/api/login/oauth/revoke", other.AccessToken, "access_token")
	if status != http.StatusOK || !introspectionActive(t, server.URL, b, other.AccessToken) {
		t.Fatal("client revoked a token belonging to another application")
	}
}

func TestWechatRefreshSession(t *testing.T) {
	initializeProbe(t, true)
	t.Run("rotation-disabled-revokes-shared-refresh-tokens", func(t *testing.T) {
		owner := fmt.Sprintf("wx-no-rotation-%d", time.Now().UnixNano())
		app := createProbeApplication(t, owner, "mini", "no-rotation-mini")
		app.DisableRefreshRotation = true
		original := miniToken(t, app, "new-test-code")
		successor, err := refreshProbe(app, original.RefreshToken)
		if err != nil {
			t.Fatal("non-rotating refresh failed")
		}
		if verifiedSubject(t, app, original.AccessToken) != verifiedSubject(t, app, successor.AccessToken) {
			t.Fatal("refresh changed subject")
		}
		if successor.RefreshToken != original.RefreshToken {
			t.Fatal("non-rotating refresh must preserve the shared refresh token")
		}
		if _, err := refreshProbe(app, original.RefreshToken); err != nil {
			t.Fatal("non-rotating parent could not be reused")
		}
		if tokenError, err := object.RevokeToken(app, app.ClientSecret, original.RefreshToken, "refresh_token"); err != nil || tokenError != nil {
			t.Fatal("parent revocation failed")
		}
		parent, err := object.GetTokenByAccessToken(original.AccessToken)
		if err != nil || parent == nil || parent.ExpiresIn > 0 {
			t.Fatal("revocation did not expire the parent")
		}
		current, err := object.GetTokenByAccessToken(successor.AccessToken)
		if err != nil || current == nil || current.ExpiresIn > 0 {
			t.Fatal("native revocation must expire tokens sharing the refresh token")
		}
		if _, err := refreshProbe(app, successor.RefreshToken); err == nil {
			t.Fatal("revoked shared refresh token accepted")
		}
	})
}
