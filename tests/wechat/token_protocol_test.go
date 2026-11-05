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
)

func TestWechatTokenHTTPProtocol(t *testing.T) {
	initializeProbe(t, true)
	web.Router("/api/login/oauth/access_token", &controllers.ApiController{}, "POST:GetOAuthToken")
	web.Router("/api/login/oauth/refresh_token", &controllers.ApiController{}, "POST:RefreshToken")
	app := createProbeApplication(t, fmt.Sprintf("wx-protocol-%d", time.Now().UnixNano()), "mini", "protocol-mini")
	server := httptest.NewServer(web.BeeApp.Handlers)
	defer server.Close()
	status, fields := memberRequestAt(t, server.URL, "access_token", app,
		url.Values{"code": {"new-test-code"}, "tag": {"wechat_miniprogram"}, "grant_type": {"token"}})
	if status != http.StatusOK {
		t.Fatalf("miniapp HTTP login failed: status=%d", status)
	}
	var access, refresh string
	if json.Unmarshal(fields["accessToken"], &access) != nil ||
		json.Unmarshal(fields["refreshToken"], &refresh) != nil || access == "" || refresh == "" {
		t.Fatal("actual miniapp login JSON no longer uses the verified camelCase mapping")
	}
	subject := verifiedSubject(t, app, access)
	status, fields = memberRequestAt(t, server.URL, "refresh_token", app,
		url.Values{"refresh_token": {refresh}, "grant_type": {"refresh_token"}})
	if status != http.StatusOK ||
		json.Unmarshal(fields["access_token"], &access) != nil ||
		json.Unmarshal(fields["refresh_token"], &refresh) != nil ||
		verifiedSubject(t, app, access) != subject {
		t.Fatal("actual refresh JSON no longer uses the verified OAuth snake_case mapping")
	}
}
