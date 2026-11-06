package wechat_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/casdoor/casdoor/object"
)

func TestWechatNativeIdentitySurvivesMissingUnionID(t *testing.T) {
	initializeProbe(t, true)
	owner := fmt.Sprintf("wx-native-alias-%d", time.Now().UnixNano())
	a := createProbeApplication(t, owner, "a", "native-a")
	b := createProbeApplication(t, owner, "b", "native-b")
	subject := verifiedSubject(t, a, miniToken(t, a, "no-union").AccessToken)
	for _, login := range []struct {
		app  *object.Application
		code string
	}{{a, "new-test-code"}, {b, "new-test-code"}, {a, "no-union"}, {b, "no-union"}} {
		if verifiedSubject(t, login.app, miniToken(t, login.app, login.code).AccessToken) != subject {
			t.Fatal("native AppID binding changed the original subject")
		}
	}
	user, err := object.GetUserByUserId(owner, subject)
	if err != nil || user == nil {
		t.Fatal("native identity read failed")
	}
	var bindings map[string]string
	if err := json.Unmarshal([]byte(user.Properties["oauth_WeChat_extra"]), &bindings); err != nil {
		t.Fatal(err)
	}
	if bindings["wechat_unionid"] != "same-real-union" ||
		bindings["wechat_openid_native-a"] != "mini-open" ||
		bindings["wechat_openid_native-b"] != "mini-open" {
		t.Fatal("native properties lost verified identity aliases")
	}
}

func TestWechatNativeIdentityRetainsRegistrationAfterProfileFailure(t *testing.T) {
	initializeProbe(t, true)
	owner := fmt.Sprintf("wx-native-failure-%d", time.Now().UnixNano())
	app := createProbeApplication(t, owner, "mini", "native-failure-mini")
	db := probeDatabase(t)
	if _, err := db.Exec("CREATE TRIGGER wechat_profile_failure BEFORE UPDATE ON `user` FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'injected profile failure'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec("DROP TRIGGER IF EXISTS wechat_profile_failure") })
	token, tokenError, err := object.GetWechatMiniProgramToken(app, "no-union", "", false,
		"127.0.0.1:8000", "", "", "en")
	if err == nil || token != nil || tokenError != nil || probeAccountCount(t, owner) != 1 {
		t.Fatal("profile failure did not leave exactly the registered native account")
	}
	user, err := object.GetUserByField(owner, "WeChat", "openid:native-failure-mini:mini-open")
	if err != nil || user == nil {
		t.Fatal("native registration was not persisted before profile failure")
	}
	if _, err := db.Exec("DROP TRIGGER wechat_profile_failure"); err != nil {
		t.Fatal(err)
	}
	if verifiedSubject(t, app, miniToken(t, app, "new-test-code").AccessToken) != user.Id ||
		probeAccountCount(t, owner) != 1 {
		t.Fatal("UnionID upgrade after profile failure created another account")
	}
}
