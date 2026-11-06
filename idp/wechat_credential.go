package idp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type WechatAppCredential struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

func FetchWechatAppCredential(client *http.Client, appID, secret string) (*WechatAppCredential, error) {
	body, err := json.Marshal(map[string]any{"grant_type": "client_credential",
		"appid": appID, "secret": secret, "force_refresh": false})
	if err != nil {
		return nil, fmt.Errorf("encode WeChat credential request: %w", err)
	}
	// Stable-token requests never invalidate another process's still-valid credential.
	response, err := client.Post("https://api.weixin.qq.com/cgi-bin/stable_token", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("request WeChat application credential: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("WeChat credential HTTP status: %d", response.StatusCode)
	}
	var result struct {
		WechatAppCredential
		ErrCode int `json:"errcode"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode WeChat credential: %w", err)
	}
	if result.ErrCode != 0 || result.AccessToken == "" || result.ExpiresIn <= 0 {
		return nil, fmt.Errorf("invalid WeChat application credential: %d", result.ErrCode)
	}
	return &result.WechatAppCredential, nil
}
