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

func memberRequest(t *testing.T, server string, app *object.Application, values url.Values) (int, map[string]json.RawMessage) {
	return memberRequestAt(t, server, "member-identity", app, values)
}

func memberRequestAt(t *testing.T, server, path string, app *object.Application, values url.Values) (int, map[string]json.RawMessage) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, server+"/api/login/oauth/"+path, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(app.ClientId, app.ClientSecret)
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal("member identity request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal("member identity response read failed")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return response.StatusCode, nil
	}
	return response.StatusCode, fields
}

func TestWechatMemberIdentity(t *testing.T) {
	initializeProbe(t, true)
	web.Router("/api/login/oauth/member-identity", &controllers.ApiController{}, "POST:MemberIdentity")
	owner := fmt.Sprintf("wx-reader-%d", time.Now().UnixNano())
	app := createProbeApplication(t, owner, "mini", "reader-mini")
	if err := json.Unmarshal([]byte(`{"memberApiScopes":["profile:read","wechat:read"]}`), app); err != nil {
		t.Fatal(err)
	}
	if _, err := object.UpdateApplication(app.GetId(), app, true, "en", nil); err != nil {
		t.Fatal("member application scope update failed")
	}
	var err error
	app, err = object.GetApplication(app.GetId())
	if err != nil || app == nil {
		t.Fatal("member application persistence read failed")
	}
	denied := createProbeApplication(t, owner, "denied", "reader-denied")
	subject := verifiedSubject(t, app, miniToken(t, app, "new-test-code").AccessToken)
	server := httptest.NewServer(web.BeeApp.Handlers)
	defer server.Close()
	values := url.Values{"subject": {subject}, "app_id": {"reader-mini"}}
	status, fields := memberRequest(t, server.URL, app, values)
	if status != http.StatusOK {
		t.Fatalf("member identity endpoint failed: status=%d", status)
	}
	var returnedSubject, openID string
	_ = json.Unmarshal(fields["subject"], &returnedSubject)
	_ = json.Unmarshal(fields["openId"], &openID)
	if returnedSubject != subject || openID != "mini-open" {
		t.Fatal("reader did not return the verified app identity")
	}
	for _, forbidden := range []string{"properties", "password", "session_key", "accessToken", "refreshToken"} {
		if _, exists := fields[forbidden]; exists {
			t.Fatal("reader leaked an unapproved field")
		}
	}
	status, _ = memberRequest(t, server.URL, denied, values)
	if status != http.StatusForbidden {
		t.Fatal("application without member scope queried identity")
	}
	values.Set("app_id", "reader-denied")
	status, _ = memberRequest(t, server.URL, app, values)
	if status != http.StatusForbidden {
		t.Fatal("reader queried an unrelated AppID")
	}
}

func TestWechatCurrentMemberState(t *testing.T) {
	initializeProbe(t, true)
	web.Router("/api/login/oauth/member-identity", &controllers.ApiController{}, "POST:MemberIdentity")
	web.Router("/api/login/oauth/introspect", &controllers.ApiController{}, "POST:IntrospectToken")
	owner := fmt.Sprintf("wx-state-%d", time.Now().UnixNano())
	app := createProbeApplication(t, owner, "mini", "state-mini")
	app.MemberApiScopes = []string{"profile:read"}
	if _, err := object.UpdateApplication(app.GetId(), app, true, "en", nil); err != nil {
		t.Fatal("state application scope update failed")
	}
	var err error
	app, err = object.GetApplication(app.GetId())
	if err != nil || app == nil {
		t.Fatal("state application read failed")
	}
	original := miniToken(t, app, "new-test-code")
	subject := verifiedSubject(t, app, original.AccessToken)
	user, err := object.GetUserByUserId(owner, subject)
	if err != nil || user == nil {
		t.Fatal("current member not found")
	}
	server := httptest.NewServer(web.BeeApp.Handlers)
	defer server.Close()
	role := &object.Role{Owner: owner, Name: "restricted-member", IsEnabled: true, Users: []string{user.GetId()}}
	if _, err := object.AddRole(role); err != nil {
		t.Fatal("restricted role create failed")
	}
	values := url.Values{"subject": {subject}}
	status, fields := memberRequest(t, server.URL, app, values)
	var roles []string
	if status != http.StatusOK || json.Unmarshal(fields["roles"], &roles) != nil ||
		len(roles) != 1 || roles[0] != role.Name {
		t.Fatal("identity reader did not return current restricted role")
	}
	role.Users = []string{}
	if _, err := object.UpdateRole(role.GetId(), role, true, "en"); err != nil {
		t.Fatal("restricted role removal failed")
	}
	_, fields = memberRequest(t, server.URL, app, values)
	if json.Unmarshal(fields["roles"], &roles) != nil || len(roles) != 0 {
		t.Fatal("removed role remained in current identity")
	}
	user.IsForbidden = true
	if _, err := object.UpdateUser(user.GetId(), user, []string{"is_forbidden"}, true); err != nil {
		t.Fatal("member disable failed")
	}
	if introspectionActive(t, server.URL, app, original.AccessToken) {
		t.Fatal("disabled member access token remained active")
	}
	if _, err := refreshProbe(app, original.RefreshToken); err == nil {
		t.Fatal("disabled member refreshed token")
	}
	_, fields = memberRequest(t, server.URL, app, values)
	var disabled bool
	if json.Unmarshal(fields["isForbidden"], &disabled) != nil || !disabled {
		t.Fatal("background reader did not report disabled member")
	}
	user.IsForbidden = false
	if _, err := object.UpdateUser(user.GetId(), user, []string{"is_forbidden"}, true); err != nil {
		t.Fatal("member enable failed")
	}
	if introspectionActive(t, server.URL, app, original.AccessToken) {
		t.Fatal("unban revived revoked token")
	}
	fresh := miniToken(t, app, "new-test-code")
	if !introspectionActive(t, server.URL, app, fresh.AccessToken) ||
		verifiedSubject(t, app, fresh.AccessToken) != subject {
		t.Fatal("enabled member could not establish a fresh session")
	}
}
