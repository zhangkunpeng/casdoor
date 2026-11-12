package routers

import (
	"net/http/httptest"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
)

func TestProviderHintReactHandoff(t *testing.T) {
	request := httptest.NewRequest("GET", "/login/oauth/authorize?provider_hint=wechat&__casdoor_provider_hint_react=1", nil)
	response := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(response, request)
	if serveProviderHintRedirectPage(ctx) {
		t.Fatal("QR handoff must reach the existing React login page instead of redirecting again")
	}
	if response.Body.Len() != 0 {
		t.Fatal("handoff must not write a redirect page")
	}
}
