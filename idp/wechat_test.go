package idp

import (
	"golang.org/x/oauth2"
	"testing"
)

func TestOfficialAccountTicketUsesNativeIdentifier(t *testing.T) {
	for _, identity := range []string{"real-union", "raw-official-open"} {
		t.Run(identity, func(t *testing.T) {
			Lock.Lock()
			WechatCacheMap = map[string]WechatCacheMapValue{
				"ticket": {IsScanned: true, WechatUnionId: identity, HasUnionId: identity == "real-union", ProviderName: "official"},
			}
			Lock.Unlock()
			t.Cleanup(func() { Lock.Lock(); WechatCacheMap = nil; Lock.Unlock() })
			provider := NewWeChatIdProvider("website-app", "unused", "")
			user, err := provider.GetUserInfo(&oauth2.Token{AccessToken: "wechat_oa:ticket"})
			if err != nil {
				t.Fatal(err)
			}
			if user.Id != identity || user.Username != "wx_user_"+identity || user.Extra != nil {
				t.Fatalf("native ticket identity changed: %#v", user)
			}
			if (user.UnionId != "") != (identity == "real-union") {
				t.Fatal("OpenID fallback was treated as UnionID")
			}
			if _, err := provider.GetUserInfo(&oauth2.Token{AccessToken: "wechat_oa:ticket"}); err == nil {
				t.Fatal("ticket replay succeeded")
			}
		})
	}
}
