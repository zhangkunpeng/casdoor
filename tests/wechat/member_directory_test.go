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
	"github.com/casdoor/casdoor/object"
)

func TestWechatMemberDirectory(t *testing.T) {
	initializeProbe(t, true)
	registerNativeMemberAPI()
	owner := fmt.Sprintf("wx-directory-%d", time.Now().UnixNano())
	app := createProbeApplication(t, owner, "directory", "directory-mini")
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
	for _, subject := range []string{"Member/: ", "member/: "} {
		status, fields := nativeMemberRequest(t, server.URL, "/api/get-user", app, "",
			url.Values{"owner": {owner}, "userId": {subject}}, nil)
		var returned string
		if status != http.StatusOK || json.Unmarshal(fields["id"], &returned) != nil || returned != subject {
			t.Fatal("native exact subject read failed")
		}
	}
	search := url.Values{"owner": {owner}, "field": {"displayName"}, "value": {"directory-probe"}, "p": {"1"}, "pageSize": {"1"}}
	for page := 1; page <= 2; page++ {
		search.Set("p", fmt.Sprint(page))
		status, fields := nativeMemberRequest(t, server.URL, "/api/get-users", app, "", search, nil)
		var users []object.User
		if status != http.StatusOK || json.Unmarshal(fields["result"], &users) != nil || len(users) != 1 ||
			users[0].Owner != owner || users[0].Phone != "13800000000" {
			t.Fatal("native directory pagination or phone contract changed")
		}
	}
	literal := &object.User{Owner: owner, Name: "literal", Id: "literal-subject", DisplayName: `literal-A%_\-target`}
	if _, err := object.AddUser(literal, "en"); err != nil {
		t.Fatal("literal directory member creation failed")
	}
	search.Set("p", "1")
	search.Set("value", `literal-A\%\_\\`)
	status, fields := nativeMemberRequest(t, server.URL, "/api/get-users", app, "", search, nil)
	var users []object.User
	if status != http.StatusOK || json.Unmarshal(fields["result"], &users) != nil ||
		len(users) != 1 || users[0].Id != literal.Id {
		t.Fatal("native literal LIKE escape did not match the exact keyword")
	}
}
