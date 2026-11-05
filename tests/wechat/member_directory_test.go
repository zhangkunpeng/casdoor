package wechat_test

import (
	"encoding/json"
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

func TestWechatMemberDirectory(t *testing.T) {
	initializeProbe(t, true)
	web.Router("/api/login/oauth/member-directory", &controllers.ApiController{}, "POST:MemberDirectory")
	owner := fmt.Sprintf("wx-directory-%d", time.Now().UnixNano())
	app := createProbeApplication(t, owner, "directory", "directory-mini")
	app.MemberApiScopes = []string{"directory:read"}
	if _, err := object.UpdateApplication(app.GetId(), app, true, "en", nil); err != nil {
		t.Fatal("directory scopes update failed")
	}
	denied := createProbeApplication(t, owner, "denied", "directory-denied")
	for i, subject := range []string{"Member/: ", "member/: "} {
		user := &object.User{Owner: owner, Name: fmt.Sprintf("member-%d", i), Id: subject,
			DisplayName: fmt.Sprintf("directory-probe-%d", i), Phone: "13800000000"}
		if _, err := object.AddUser(user, "en"); err != nil {
			t.Fatal("directory member creation failed")
		}
		persisted, err := object.GetUserByUserId(owner, subject)
		if err != nil || persisted == nil || persisted.Id != subject {
			t.Fatal("directory exact subject persistence failed")
		}
	}
	server := httptest.NewServer(web.BeeApp.Handlers)
	defer server.Close()
	encoded, _ := json.Marshal([]string{"Member/: ", "member/: ", "missing"})
	values := url.Values{"subjects": {string(encoded)}}
	status, fields := memberRequestAt(t, server.URL, "member-directory", app, values)
	var items []object.MemberDirectoryItem
	if status != http.StatusOK || json.Unmarshal(fields["items"], &items) != nil || len(items) != 2 ||
		items[0].Subject != "Member/: " || items[1].Subject != "member/: " {
		t.Fatalf("directory exact read failed: status=%d", status)
	}
	for _, item := range items {
		if item.Organization != owner || item.PhoneMask == "13800000000" {
			t.Fatal("directory returned untrusted organization or full phone")
		}
	}
	if status, _ := memberRequestAt(t, server.URL, "member-directory", denied, values); status != http.StatusForbidden {
		t.Fatal("unprivileged application enumerated directory")
	}
	search := url.Values{"keyword": {"directory-probe"}, "match_nickname": {"true"}, "match_phone": {"false"}}
	status, fields = memberRequestAt(t, server.URL, "member-directory", app, search)
	var subjects []string
	if status != http.StatusOK || json.Unmarshal(fields["subjects"], &subjects) != nil || len(subjects) != 2 {
		t.Fatal("directory search failed")
	}
	encoded, _ = json.Marshal([]string{"Member/: ", "Member/: "})
	values.Set("subjects", string(encoded))
	if status, _ := memberRequestAt(t, server.URL, "member-directory", app, values); status != http.StatusBadRequest {
		t.Fatal("ambiguous directory batch accepted")
	}
}
