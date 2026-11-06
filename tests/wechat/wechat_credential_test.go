package wechat_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/controllers"
	"github.com/casdoor/casdoor/object"
)

type credentialTransport struct {
	base  http.RoundTripper
	calls *atomic.Int32
}

func (r credentialTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Host == "api.weixin.qq.com" {
		if request.URL.Path == "/cgi-bin/token" {
			return nil, fmt.Errorf("deprecated WeChat token endpoint requested")
		}
		if request.URL.Path == "/cgi-bin/stable_token" {
			r.calls.Add(1)
		}
	}
	return r.base.RoundTrip(request)
}

func TestWechatApplicationCredential(t *testing.T) {
	initializeProbe(t, true)
	web.Router("/api/login/oauth/member-wechat-credential", &controllers.ApiController{}, "POST:MemberWechatCredential")
	base, calls := http.DefaultTransport, &atomic.Int32{}
	http.DefaultTransport = credentialTransport{base, calls}
	t.Cleanup(func() { http.DefaultTransport = base })
	appID := fmt.Sprintf("credential-%d", time.Now().UnixNano())
	app := createProbeApplication(t, appID, "mini", appID)
	app.Scopes = []*object.ScopeItem{{Name: "wechat:credential"}}
	if _, err := object.UpdateApplication(app.GetId(), app, true, "en", nil); err != nil {
		t.Fatal("credential scopes update failed")
	}
	var err error
	app, err = object.GetApplication(app.GetId())
	if err != nil || app == nil {
		t.Fatal("credential application read failed")
	}
	var wg sync.WaitGroup
	successes := &atomic.Int32{}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			value, err := object.GetMemberWechatCredential(app, appID)
			if err == nil && value.AccessToken == "test-only" && value.ExpiresAt > time.Now().Unix() {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 8 || calls.Load() != 1 {
		t.Fatal("credential manager did not share one upstream acquisition")
	}
	for _, result := range runProbeProcesses(t, app, "", appID) {
		if result.AccessToken != "test-only" {
			t.Fatal("another Casdoor process did not reuse the persisted credential")
		}
	}
	server := httptest.NewServer(web.BeeApp.Handlers)
	defer server.Close()
	denied := createProbeApplication(t, app.Organization, "denied", "credential-denied")
	if status := memberMutation(t, server.URL, "member-wechat-credential", denied, url.Values{"app_id": {appID}}); status != http.StatusForbidden {
		t.Fatal("application without credential scope acquired an upstream credential")
	}
	if status := memberMutation(t, server.URL, "member-wechat-credential", app, url.Values{"app_id": {"unrelated"}}); status != http.StatusForbidden {
		t.Fatal("credential manager accepted an unrelated AppID")
	}
	if status := memberMutation(t, server.URL, "member-wechat-credential", app, url.Values{"app_id": {appID}}); status != http.StatusOK {
		t.Fatal("scoped server did not acquire the managed credential")
	}
}
