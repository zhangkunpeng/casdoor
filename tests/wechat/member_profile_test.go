package wechat_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/controllers"
	"github.com/casdoor/casdoor/object"
)

func TestWechatMemberProfile(t *testing.T) {
	initializeProbe(t, true)
	web.Router("/api/login/oauth/member-profile", &controllers.ApiController{}, "POST:MemberProfile")
	owner := fmt.Sprintf("wx-profile-%d", time.Now().UnixNano())
	app := createProbeApplication(t, owner, "mini", "profile-mini")
	app.MemberApiScopes = []string{"profile:read", "profile:write"}
	if _, err := object.UpdateApplication(app.GetId(), app, true, "en", nil); err != nil {
		t.Fatal("profile scopes update failed")
	}
	var err error
	app, err = object.GetApplication(app.GetId())
	if err != nil || app == nil {
		t.Fatal("profile application persistence read failed")
	}
	session := miniToken(t, app, "new-test-code")
	subject := verifiedSubject(t, app, session.AccessToken)
	server := httptest.NewServer(web.BeeApp.Handlers)
	defer server.Close()
	values := url.Values{"access_token": {session.AccessToken}, "nickname": {"本人昵称"},
		"avatar": {"https://assets.example.test/avatar.png"}, "subject": {"untrusted-other"}}
	assertProfile := func(nickname, avatar string) *object.User {
		t.Helper()
		user, err := object.GetUserByUserId(app.Organization, subject)
		if err != nil || user == nil || user.DisplayName != nickname || user.Avatar != avatar {
			t.Fatal("profile mutation did not persist on exactly the authenticated subject")
		}
		return user
	}
	for i := 0; i < 2; i++ {
		if status := memberMutation(t, server.URL, "member-profile", app, values); status != http.StatusOK {
			t.Fatalf("profile update failed: status=%d", status)
		}
		assertProfile("本人昵称", "https://assets.example.test/avatar.png")
	}
	values.Del("avatar")
	values.Set("nickname", "新昵称")
	if status := memberMutation(t, server.URL, "member-profile", app, values); status != http.StatusOK {
		t.Fatal("partial nickname update rejected")
	}
	user := assertProfile("新昵称", "https://assets.example.test/avatar.png")
	for _, avatar := range []string{"http://assets.example.test/a", "javascript:alert(1)", "https://user:password@example.test/a"} {
		values.Set("avatar", avatar)
		if status := memberMutation(t, server.URL, "member-profile", app, values); status != http.StatusBadRequest {
			t.Fatal("untrusted avatar reference accepted")
		}
		assertProfile("新昵称", "https://assets.example.test/avatar.png")
	}
	values.Del("avatar")
	values.Set("access_token", session.IdToken)
	if status := memberMutation(t, server.URL, "member-profile", app, values); status != http.StatusUnauthorized {
		t.Fatal("ID token authorized profile mutation")
	}
	values.Set("access_token", session.AccessToken)
	otherApp := createProbeApplication(t, owner, "other-mini", "profile-other")
	otherApp.MemberApiScopes = []string{"profile:write"}
	if _, err := object.UpdateApplication(otherApp.GetId(), otherApp, true, "en", nil); err != nil {
		t.Fatal("other application scopes update failed")
	}
	if status := memberMutation(t, server.URL, "member-profile", otherApp, values); status != http.StatusUnauthorized {
		t.Fatal("another application's credentials authorized profile mutation")
	}
	values.Set("nickname", "失败后重试")
	db := probeDatabase(t)
	if _, err := db.Exec("CREATE TRIGGER xueda_profile_failure BEFORE UPDATE ON `user` FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'injected profile write failure'"); err != nil {
		t.Fatal("profile failure trigger creation failed")
	}
	t.Cleanup(func() { db.Exec("DROP TRIGGER IF EXISTS xueda_profile_failure") })
	if status := memberMutation(t, server.URL, "member-profile", app, values); status != http.StatusServiceUnavailable {
		t.Fatal("profile persistence failure reported success")
	}
	assertProfile("新昵称", "https://assets.example.test/avatar.png")
	if _, err := db.Exec("DROP TRIGGER xueda_profile_failure"); err != nil {
		t.Fatal("profile failure trigger cleanup failed")
	}
	if status := memberMutation(t, server.URL, "member-profile", app, values); status != http.StatusOK {
		t.Fatal("profile write could not retry after rollback")
	}
	user = assertProfile("失败后重试", "https://assets.example.test/avatar.png")
	user.IsForbidden = true
	if _, err := object.UpdateUser(user.GetId(), user, []string{"is_forbidden"}, true); err != nil {
		t.Fatal("member disable failed")
	}
	if status := memberMutation(t, server.URL, "member-profile", app, values); status != http.StatusUnauthorized {
		t.Fatal("disabled subject mutated profile")
	}
	users, _ := probeAccountCounts(t, app.Organization)
	if users != 1 {
		t.Fatal("profile update created another account")
	}
}
