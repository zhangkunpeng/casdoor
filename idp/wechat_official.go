package idp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

func ResolveWechatOfficialAccountIdentity(client *http.Client, appId, secret, openId string) (*WechatUserInfo, error) {
	if appId == "" || secret == "" || openId == "" {
		return nil, fmt.Errorf("missing official account identity parameters")
	}
	token, message, err := GetWechatOfficialAccountAccessToken(appId, secret)
	if err != nil {
		return nil, fmt.Errorf("get official account access token: %w", err)
	}
	if message != "" || token == "" {
		return nil, fmt.Errorf("official account access token unavailable")
	}
	query := url.Values{"access_token": {token}, "openid": {openId}, "lang": {"zh_CN"}}
	response, err := client.Get("https://api.weixin.qq.com/cgi-bin/user/info?" + query.Encode())
	if err != nil {
		return nil, fmt.Errorf("get official account user: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("official account user HTTP status: %d", response.StatusCode)
	}
	var result struct {
		WechatUserInfo
		ErrCode int `json:"errcode"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode official account user: %w", err)
	}
	if result.ErrCode != 0 {
		return nil, fmt.Errorf("official account user API error: %d", result.ErrCode)
	}
	if result.Openid != openId {
		return nil, fmt.Errorf("official account OpenID mismatch")
	}
	return &result.WechatUserInfo, nil
}
