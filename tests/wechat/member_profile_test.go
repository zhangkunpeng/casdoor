package wechat_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/authz"
	"github.com/casdoor/casdoor/controllers"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/routers"
)

var nativeMemberAPIOnce sync.Once

func registerNativeMemberAPI() {
	nativeMemberAPIOnce.Do(func() {
		authz.InitApi()
		for path, method := range map[string]string{
			"/api/get-user": "GET:GetUser", "/api/get-users": "GET:GetUsers", "/api/update-user": "POST:UpdateUser",
			"/api/upload-resource": "POST:UploadResource",
		} {
			web.Router(path, &controllers.ApiController{}, method)
			web.InsertFilter(path, web.BeforeStatic, routers.RequestBodyFilter)
			web.InsertFilter(path, web.BeforeRouter, routers.AutoSigninFilter)
			web.InsertFilter(path, web.BeforeRouter, routers.ApiFilter)
		}
	})
}

func nativeMemberRequest(t *testing.T, server, path string, app *object.Application, bearer string, values url.Values, payload any) (int, map[string]json.RawMessage) {
	t.Helper()
	method := http.MethodGet
	var body io.Reader
	if payload != nil {
		method = http.MethodPost
		content, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(content)
	}
	req, err := http.NewRequest(method, server+path+"?"+values.Encode(), body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	} else {
		req.SetBasicAuth(app.ClientId, app.ClientSecret)
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal("native member request failed")
	}
	defer response.Body.Close()
	var envelope struct {
		Status string
		Data   json.RawMessage
	}
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatal("native response decode failed")
	}
	if envelope.Status != "ok" {
		return response.StatusCode, nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(envelope.Data, &fields) != nil {
		fields = map[string]json.RawMessage{"result": envelope.Data}
	}
	return response.StatusCode, fields
}

func TestWechatMemberProfile(t *testing.T) {
	initializeProbe(t, true)
	registerNativeMemberAPI()
	owner := fmt.Sprintf("wx-profile-%d", time.Now().UnixNano())
	app := createProbeApplication(t, owner, "mini", "profile-mini")
	session := miniToken(t, app, "new-test-code")
	subject := verifiedSubject(t, app, session.AccessToken)
	server := httptest.NewServer(web.BeeApp.Handlers)
	defer server.Close()
	member, err := object.GetUserByUserId(owner, subject)
	if err != nil || member == nil {
		t.Fatal("native profile target read failed")
	}
	payload := map[string]string{"owner": owner, "name": member.Name, "id": subject,
		"displayName": "本人昵称", "avatar": "https://assets.example.test/avatar.png"}
	values := url.Values{"id": {member.GetId()}, "columns": {"displayName,avatar"}}
	update := func(bearer string) bool {
		t.Helper()
		status, fields := nativeMemberRequest(t, server.URL, "/api/update-user", app, bearer, values, payload)
		return status == http.StatusOK && fields != nil
	}
	assertProfile := func(nickname, avatar string) *object.User {
		t.Helper()
		user, err := object.GetUserByUserId(app.Organization, subject)
		if err != nil || user == nil || user.DisplayName != nickname || user.Avatar != avatar {
			t.Fatal("profile mutation did not persist on exactly the authenticated subject")
		}
		return user
	}
	for i := 0; i < 2; i++ {
		if !update(session.AccessToken) {
			t.Fatal("native self profile update failed")
		}
		assertProfile("本人昵称", "https://assets.example.test/avatar.png")
	}
	delete(payload, "avatar")
	values.Set("columns", "displayName")
	payload["displayName"] = "新昵称"
	if !update(session.AccessToken) {
		t.Fatal("partial nickname update rejected")
	}
	user := assertProfile("新昵称", "https://assets.example.test/avatar.png")
	if update(session.IdToken) {
		t.Fatal("ID token authorized profile mutation")
	}
	otherApp := createProbeApplication(t, owner, "other-mini", "profile-other")
	other := miniToken(t, otherApp, "different-wechat")
	if update(other.AccessToken) {
		t.Fatal("another member authorized profile mutation")
	}
	payload["displayName"] = "失败后重试"
	db := probeDatabase(t)
	if _, err := db.Exec("CREATE TRIGGER xueda_profile_failure BEFORE UPDATE ON `user` FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'injected profile write failure'"); err != nil {
		t.Fatal("profile failure trigger creation failed")
	}
	t.Cleanup(func() { db.Exec("DROP TRIGGER IF EXISTS xueda_profile_failure") })
	if update(session.AccessToken) {
		t.Fatal("profile persistence failure reported success")
	}
	assertProfile("新昵称", "https://assets.example.test/avatar.png")
	if _, err := db.Exec("DROP TRIGGER xueda_profile_failure"); err != nil {
		t.Fatal("profile failure trigger cleanup failed")
	}
	if !update(session.AccessToken) {
		t.Fatal("profile write could not retry after rollback")
	}
	user = assertProfile("失败后重试", "https://assets.example.test/avatar.png")
	user.IsForbidden = true
	if _, err := object.UpdateUser(user.GetId(), user, []string{"is_forbidden"}, true); err != nil {
		t.Fatal("member disable failed")
	}
	payload["displayName"] = "禁止更新"
	if update(session.AccessToken) {
		t.Fatal("disabled subject mutated profile")
	}
	users, _ := probeAccountCounts(t, app.Organization)
	if users != 2 {
		t.Fatal("profile update created another account")
	}
}
