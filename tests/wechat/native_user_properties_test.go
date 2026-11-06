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
		t.Fatal("OAuth request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal("OAuth response read failed")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return response.StatusCode, nil
	}
	return response.StatusCode, fields
}

func TestWechatMemberScopes(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		app     *object.Application
		allowed bool
	}{
		{"missing-application", nil, false},
		{"unconfigured-scopes", &object.Application{}, false},
		{"empty-scopes", &object.Application{Scopes: []*object.ScopeItem{}}, false},
		{"unrelated-scope", &object.Application{Scopes: []*object.ScopeItem{{Name: "profile:write"}}}, false},
		{"wildcard-scope", &object.Application{Scopes: []*object.ScopeItem{{Name: "phone:.*"}}}, false},
		{"nil-scope-item", &object.Application{Scopes: []*object.ScopeItem{nil}}, false},
		{"explicit-native-scope", &object.Application{Scopes: []*object.ScopeItem{nil, {Name: "phone:write"}}}, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if object.MemberScopeAllowed(scenario.app, "phone:write") != scenario.allowed {
				t.Fatal("member scope did not require an exact native scope name")
			}
		})
	}
}

func TestWechatNativeUserProperties(t *testing.T) {
	initializeProbe(t, true)
	registerNativeMemberAPI()
	owner := fmt.Sprintf("wx-reader-%d", time.Now().UnixNano())
	app := createProbeApplication(t, owner, "mini", "reader-mini")
	organization, err := object.GetOrganization("admin/" + owner)
	if err != nil || organization == nil {
		t.Fatal("native user organization read failed")
	}
	organization.AccountItems = []*object.AccountItem{{Name: "Properties", ViewRule: "Admin", ModifyRule: "Admin"}}
	if _, err := object.UpdateOrganization("admin/"+owner, organization, true, "en"); err != nil {
		t.Fatal("native properties permission configuration failed")
	}
	session := miniToken(t, app, "new-test-code")
	subject := verifiedSubject(t, app, session.AccessToken)
	server := httptest.NewServer(web.BeeApp.Handlers)
	defer server.Close()
	values := url.Values{"owner": {owner}, "userId": {subject}}
	readBindings := func() map[string]string {
		t.Helper()
		status, fields := nativeMemberRequest(t, server.URL, "/api/get-user", app, "", values, nil)
		var returnedSubject string
		var properties, bindings map[string]string
		if status != http.StatusOK || json.Unmarshal(fields["id"], &returnedSubject) != nil ||
			returnedSubject != subject || json.Unmarshal(fields["properties"], &properties) != nil ||
			json.Unmarshal([]byte(properties["oauth_WeChat_extra"]), &bindings) != nil {
			t.Fatal("native user read did not expose the verified WeChat property")
		}
		return bindings
	}
	if readBindings()["wechat_openid_reader-mini"] != "mini-open" {
		t.Fatal("native user properties omitted the miniapp OpenID")
	}
	other := createProbeApplication(t, owner, "other", "reader-other")
	if verifiedSubject(t, other, miniToken(t, other, "new-test-code").AccessToken) != subject {
		t.Fatal("another verified AppID changed the account subject")
	}
	miniToken(t, app, "new-test-code")
	assertBindings := func() {
		t.Helper()
		bindings := readBindings()
		if bindings["wechat_openid_reader-mini"] != "mini-open" || bindings["wechat_openid_reader-other"] != "mini-open" ||
			bindings["wechat_unionid"] == "" || len(bindings) != 3 {
			t.Fatal("native properties did not preserve both verified AppIDs")
		}
	}
	assertBindings()
	user, err := object.GetUserByUserId(owner, subject)
	if err != nil || user == nil {
		t.Fatal("native user mutation target read failed")
	}
	payload := map[string]any{"owner": owner, "name": user.Name, "id": subject,
		"properties": map[string]string{"oauth_WeChat_extra": `{"wechat_openid_reader-mini":"forged"}`}}
	nativeMemberRequest(t, server.URL, "/api/update-user", app, session.AccessToken,
		url.Values{"id": {user.GetId()}, "columns": {"properties"}}, payload)
	assertBindings()
	status, fields := nativeMemberRequest(t, server.URL, "/api/get-user", app, session.AccessToken, values, nil)
	var properties map[string]string
	if status != http.StatusOK || json.Unmarshal(fields["properties"], &properties) != nil ||
		properties["oauth_WeChat_extra"] != "" {
		t.Fatal("native self view exposed admin-only WeChat bindings")
	}
}

func TestWechatCurrentMemberState(t *testing.T) {
	initializeProbe(t, true)
	registerNativeMemberAPI()
	web.Router("/api/login/oauth/introspect", &controllers.ApiController{}, "POST:IntrospectToken")
	owner := fmt.Sprintf("wx-state-%d", time.Now().UnixNano())
	app := createProbeApplication(t, owner, "mini", "state-mini")
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
	values := url.Values{"owner": {owner}, "userId": {subject}}
	status, fields := nativeMemberRequest(t, server.URL, "/api/get-user", app, "", values, nil)
	var roles []*object.Role
	if status != http.StatusOK || json.Unmarshal(fields["roles"], &roles) != nil ||
		len(roles) != 1 || roles[0].Name != role.Name {
		t.Fatal("identity reader did not return current restricted role")
	}
	role.Users = []string{}
	if _, err := object.UpdateRole(role.GetId(), role, true, "en"); err != nil {
		t.Fatal("restricted role removal failed")
	}
	_, fields = nativeMemberRequest(t, server.URL, "/api/get-user", app, "", values, nil)
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
	_, fields = nativeMemberRequest(t, server.URL, "/api/get-user", app, "", values, nil)
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
