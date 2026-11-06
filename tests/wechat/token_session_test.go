package wechat_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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
	if !introspectionActive(t, server.URL, a, successor.AccessToken) ||
		!introspectionActive(t, server.URL, b, other.AccessToken) {
		t.Fatal("fresh sessions were inactive")
	}
	for i := 0; i < 2; i++ {
		status, _ := oauthRequest(t, server.URL, a, "/api/login/oauth/revoke", original.RefreshToken, "refresh_token")
		if status != http.StatusOK {
			t.Fatalf("application revocation endpoint failed: status=%d", status)
		}
		if introspectionActive(t, server.URL, a, successor.AccessToken) {
			t.Fatal("revoked successor remained active")
		}
		if !introspectionActive(t, server.URL, b, other.AccessToken) {
			t.Fatal("application logout revoked another application")
		}
	}
	if _, err := refreshProbe(a, successor.RefreshToken); err == nil {
		t.Fatal("revoked successor refresh accepted")
	}
	status, _ := oauthRequest(t, server.URL, a, "/api/login/oauth/revoke", other.AccessToken, "access_token")
	if status != http.StatusOK || !introspectionActive(t, server.URL, b, other.AccessToken) {
		t.Fatal("client revoked a token belonging to another application")
	}
}

func TestWechatRefreshSession(t *testing.T) {
	initializeProbe(t, true)
	t.Run("successor-persistence-failure-and-retry", func(t *testing.T) {
		owner := fmt.Sprintf("wx-rollback-%d", time.Now().UnixNano())
		app := createProbeApplication(t, owner, "mini", "rollback-mini")
		original := miniToken(t, app, "new-test-code")
		db := probeDatabase(t)
		trigger := "xueda_refresh_failure"
		statement := fmt.Sprintf("CREATE TRIGGER %s BEFORE INSERT ON token FOR EACH ROW "+
			"BEGIN IF NEW.organization = '%s' THEN SIGNAL SQLSTATE '45000' "+
			"SET MESSAGE_TEXT = 'isolated refresh fault'; END IF; END", trigger, owner)
		if _, err := db.Exec(statement); err != nil {
			t.Fatal("install isolated refresh fault failed")
		}
		t.Cleanup(func() { _, _ = db.Exec("DROP TRIGGER IF EXISTS " + trigger) })
		if _, err := refreshProbe(app, original.RefreshToken); err == nil {
			t.Fatal("refresh ignored successor persistence failure")
		}
		persisted, err := object.GetTokenByAccessToken(original.AccessToken)
		if err != nil || persisted == nil || persisted.ExpiresIn <= 0 {
			t.Fatal("failed rotation did not roll back parent retirement")
		}
		if _, err := db.Exec("DROP TRIGGER " + trigger); err != nil {
			t.Fatal("remove isolated refresh fault failed")
		}
		if _, err := refreshProbe(app, original.RefreshToken); err != nil {
			t.Fatal("refresh retry failed after rollback")
		}
	})
	t.Run("two-independent-processes", func(t *testing.T) {
		owner := fmt.Sprintf("wx-process-rotation-%d", time.Now().UnixNano())
		app := createProbeApplication(t, owner, "mini", "process-rotation-mini")
		original := miniToken(t, app, "new-test-code")
		successes, rejected := 0, 0
		for _, result := range runProbeProcesses(t, app, original.RefreshToken, "") {
			if result.RefreshRejected {
				rejected++
			} else {
				successes++
				if verifiedSubject(t, app, result.AccessToken) != verifiedSubject(t, app, original.AccessToken) {
					t.Fatal("cross-process rotation changed subject")
				}
			}
		}
		if successes != 1 || rejected != 1 {
			t.Fatalf("cross-process rotation failed: successes=%d rejected=%d", successes, rejected)
		}
	})
	t.Run("single-use-concurrent-rotation", func(t *testing.T) {
		owner := fmt.Sprintf("wx-rotation-%d", time.Now().UnixNano())
		app := createProbeApplication(t, owner, "mini", "rotation-mini")
		original := miniToken(t, app, "new-test-code")
		start := make(chan struct{})
		results := make(chan *object.TokenWrapper, 8)
		var wg sync.WaitGroup
		for i := 0; i < cap(results); i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				result, err := refreshProbe(app, original.RefreshToken)
				if err == nil {
					results <- result
				}
			}()
		}
		close(start)
		wg.Wait()
		close(results)
		var successor *object.TokenWrapper
		successes := 0
		for result := range results {
			successor = result
			successes++
		}
		if successes != 1 {
			t.Fatalf("refresh token consumed more than once: successes=%d", successes)
		}
		if verifiedSubject(t, app, original.AccessToken) != verifiedSubject(t, app, successor.AccessToken) {
			t.Fatal("rotation changed subject")
		}
		if _, err := refreshProbe(app, original.RefreshToken); err == nil {
			t.Fatal("used refresh token accepted again")
		}
		old, err := object.GetTokenByAccessToken(original.AccessToken)
		if err != nil || old == nil || old.ExpiresIn > 0 {
			t.Fatal("rotation did not persist retired access token")
		}
		current, err := object.GetTokenByAccessToken(successor.AccessToken)
		if err != nil || current == nil || current.ExpiresIn <= 0 {
			t.Fatal("rotation did not persist active successor")
		}
	})
}

func TestWechatRefreshRevocationRace(t *testing.T) {
	initializeProbe(t, true)
	for i := 0; i < 4; i++ {
		owner := fmt.Sprintf("wx-race-%d-%d", time.Now().UnixNano(), i)
		app := createProbeApplication(t, owner, "mini", "race-mini")
		original := miniToken(t, app, "new-test-code")
		start := make(chan struct{})
		done := make(chan struct{})
		var successor *object.TokenWrapper
		go func() {
			<-start
			successor, _ = refreshProbe(app, original.RefreshToken)
			close(done)
		}()
		close(start)
		firstTokenError, firstErr := object.RevokeToken(app, app.ClientSecret, original.RefreshToken, "refresh_token")
		<-done
		if firstErr != nil || firstTokenError != nil {
			if tokenError, err := object.RevokeToken(app, app.ClientSecret, original.RefreshToken, "refresh_token"); err != nil || tokenError != nil {
				t.Fatal("revocation retry failed")
			}
		}
		if successor != nil {
			current, err := object.GetTokenByAccessToken(successor.AccessToken)
			if err != nil || current == nil || current.ExpiresIn > 0 {
				t.Fatal("refresh escaped concurrent revocation")
			}
			if _, err := refreshProbe(app, successor.RefreshToken); err == nil {
				t.Fatal("revoked family created another successor")
			}
		}
	}
}
