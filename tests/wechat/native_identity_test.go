package wechat_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/casdoor/casdoor/object"
)

func TestWechatExistingPhoneBindingIsSingleWrite(t *testing.T) {
	initializeProbe(t, true)
	base := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = base })
	for _, code := range []string{"new-test-code", "no-union"} {
		t.Run(code, func(t *testing.T) {
			http.DefaultTransport = phoneTransport{base: base, calls: &atomic.Int32{}, used: &sync.Map{}}
			owner := fmt.Sprintf("wx-phone-link-%d", time.Now().UnixNano())
			app := createProbeApplication(t, owner, "mini", "existing-phone-mini")
			user := &object.User{Owner: owner, Name: "existing-member",
				Phone: "13800111111", CountryCode: "CN", SignupApplication: app.Name}
			if _, err := object.AddUser(user, "en"); err != nil {
				t.Fatal(err)
			}
			db := probeDatabase(t)
			if _, err := db.Exec("CREATE TRIGGER wechat_phone_link_failure BEFORE UPDATE ON `user` FOR EACH ROW BEGIN IF NEW.wechat <> '' AND JSON_EXTRACT(NULLIF(NEW.properties, ''), '$.oauth_WeChat_extra') IS NOT NULL THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'injected canonical identity failure'; END IF; END"); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { db.Exec("DROP TRIGGER IF EXISTS wechat_phone_link_failure") })
			token, tokenError, err := object.GetWechatMiniProgramToken(app, code, "retryable-phone-code", true,
				"127.0.0.1:8000", "", "", "en")
			if err == nil || token != nil || tokenError != nil {
				t.Fatal("canonical identity persistence failure did not propagate")
			}
			persisted, err := object.GetUser(user.GetId())
			if err != nil || persisted == nil {
				t.Fatal("existing phone account unavailable after failure")
			}
			if persisted.WeChat != "" || persisted.Properties["oauth_WeChat_extra"] != "" {
				t.Error("failed canonical identity update left a partial WeChat binding")
			}
			if _, err := db.Exec("DROP TRIGGER wechat_phone_link_failure"); err != nil {
				t.Fatal(err)
			}
			token, tokenError, err = object.GetWechatMiniProgramToken(app, code, "fresh-phone-code", true,
				"127.0.0.1:8000", "", "", "en")
			if err != nil || tokenError != nil || token == nil {
				t.Fatal("fresh phone authorization could not recover the existing account")
			}
			if verifiedSubject(t, app, token.AccessToken) != user.Id || probeAccountCount(t, owner) != 1 ||
				verifiedSubject(t, app, miniToken(t, app, code).AccessToken) != user.Id {
				t.Fatal("phone binding changed the existing account subject")
			}
			persisted, err = object.GetUser(user.GetId())
			if err != nil || persisted == nil {
				t.Fatal("bound existing account unavailable")
			}
			var bindings map[string]string
			if err := json.Unmarshal([]byte(persisted.Properties["oauth_WeChat_extra"]), &bindings); err != nil ||
				bindings["wechat_openid_existing-phone-mini"] != "mini-open" {
				t.Fatal("existing account did not retain its canonical AppID binding")
			}
		})
	}
}

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
