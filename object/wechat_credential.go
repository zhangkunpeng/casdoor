package object

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/casdoor/casdoor/idp"
)

type WechatCredential struct {
	Key         string `xorm:"varchar(64) pk" json:"-"`
	AccessToken string `xorm:"text" json:"-"`
	ExpiresAt   int64  `json:"-"`
}

func memberWechatProvider(application *Application, appID string) (*Provider, error) {
	for _, item := range application.Providers {
		provider, err := GetProvider("admin/" + item.Name)
		if err != nil {
			return nil, fmt.Errorf("read member WeChat provider: %w", err)
		}
		if provider == nil {
			continue
		}
		if (provider.Type == "WeChatMiniProgram" || provider.Type == "WeChat") && provider.ClientId == appID {
			return provider, nil
		}
		if provider.Type == "WeChat" && provider.ClientId2 == appID {
			copy := *provider
			copy.ClientId, copy.ClientSecret = provider.ClientId2, provider.ClientSecret2
			return &copy, nil
		}
	}
	return nil, ErrMemberAppDenied
}

func getWechatCredential(client *http.Client, provider *Provider) (*WechatCredential, error) {
	hash := sha256.Sum256([]byte(provider.ClientId + "\x00" + provider.ClientSecret))
	key := hex.EncodeToString(hash[:])
	release, err := lockCasdoorResource("wechat-credential:" + key)
	if err != nil {
		return nil, fmt.Errorf("lock WeChat credential: %w", err)
	}
	defer release()
	current := WechatCredential{Key: key}
	exists, err := ormer.Engine.Get(&current)
	if err != nil {
		return nil, fmt.Errorf("read WeChat credential: %w", err)
	}
	if exists && time.Now().Unix() < current.ExpiresAt-120 {
		return &current, nil
	}
	credential, err := idp.FetchWechatAppCredential(client, provider.ClientId, provider.ClientSecret)
	if err != nil {
		return nil, err
	}
	current.AccessToken, current.ExpiresAt = credential.AccessToken, time.Now().Unix()+credential.ExpiresIn
	if exists {
		_, err = ormer.Engine.ID(key).AllCols().Update(&current)
	} else {
		_, err = ormer.Engine.Insert(&current)
	}
	if err != nil {
		return nil, fmt.Errorf("persist WeChat credential: %w", err)
	}
	return &current, nil
}

func GetMemberWechatCredential(application *Application, appID string) (*WechatCredential, error) {
	provider, err := memberWechatProvider(application, appID)
	if err != nil {
		return nil, err
	}
	return getWechatCredential(&http.Client{Timeout: 10 * time.Second}, provider)
}
