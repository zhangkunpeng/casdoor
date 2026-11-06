package idp

import (
	"golang.org/x/oauth2"
	"testing"
)

func TestOfficialAccountTicketPreservesVerifiedWechatIdentifiers(t *testing.T) {
	Lock.Lock()
	WechatCacheMap = map[string]WechatCacheMapValue{"test-ticket": {IsScanned: true, WechatUnionId: "real-union", WechatOpenId: "official-open", AppId: "official-app", ProviderName: "official"}}
	Lock.Unlock()
	t.Cleanup(func() { Lock.Lock(); WechatCacheMap = nil; Lock.Unlock() })
	provider := NewWeChatIdProvider("website-app", "unused", "")
	user, err := provider.GetUserInfo(&oauth2.Token{AccessToken: "wechat_oa:test-ticket"})
	if err != nil {
		t.Fatal(err)
	}
	if user.Id != "real-union" || user.Extra["wechat_unionid"] != "real-union" {
		t.Fatalf("verified union identity was lost: %#v", user)
	}
	if user.Extra[BuildWechatOpenIdKey("official-app")] != "official-open" {
		t.Fatal("lost official account OpenID")
	}
	if _, err := provider.GetUserInfo(&oauth2.Token{AccessToken: "wechat_oa:test-ticket"}); err == nil {
		t.Fatal("ticket replay succeeded")
	}
}

func TestOfficialAccountTicketHasOnlyOneConcurrentConsumer(t *testing.T) {
	Lock.Lock()
	WechatCacheMap = map[string]WechatCacheMapValue{"concurrent-ticket": {IsScanned: true, WechatUnionId: "real-union", WechatOpenId: "official-open", AppId: "official-app", ProviderName: "official"}}
	Lock.Unlock()
	t.Cleanup(func() { Lock.Lock(); WechatCacheMap = nil; Lock.Unlock() })
	provider := NewWeChatIdProvider("website-app", "unused", "")
	results := make(chan bool, 16)
	for i := 0; i < 16; i++ {
		go func() {
			_, err := provider.GetUserInfo(&oauth2.Token{AccessToken: "wechat_oa:concurrent-ticket"})
			results <- err == nil
		}()
	}
	successes := 0
	for i := 0; i < 16; i++ {
		if <-results {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful consumers=%d, want 1", successes)
	}
}

func TestOfficialAccountWithoutUnionIDUsesAppScopedOpenID(t *testing.T) {
	Lock.Lock()
	WechatCacheMap = map[string]WechatCacheMapValue{
		"first":  {WechatOpenId: "same-open", AppId: "first-app"},
		"second": {WechatOpenId: "same-open", AppId: "second-app"},
	}
	Lock.Unlock()
	t.Cleanup(func() { Lock.Lock(); WechatCacheMap = nil; Lock.Unlock() })
	provider := NewWeChatIdProvider("website-app", "unused", "")
	first, err := provider.GetUserInfo(&oauth2.Token{AccessToken: "wechat_oa:first"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := provider.GetUserInfo(&oauth2.Token{AccessToken: "wechat_oa:second"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Id != "openid:first-app:same-open" || second.Id != "openid:second-app:same-open" {
		t.Fatal("OpenID fallback lost application scope")
	}
	if first.Extra["wechat_unionid"] != "" || second.Extra["wechat_unionid"] != "" {
		t.Fatal("OpenID was presented as UnionID")
	}
}
