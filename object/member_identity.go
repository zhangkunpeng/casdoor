package object

import (
	"fmt"

	"github.com/casdoor/casdoor/util"
)

type MemberIdentity struct {
	Subject      string `json:"subject"`
	Organization string `json:"organization"`
	AppId        string `json:"appId"`
	OpenId       string `json:"openId"`
}

func MemberScopeAllowed(application *Application, scope string) bool {
	return application != nil && util.InSlice(application.MemberApiScopes, scope)
}

func MemberAppAllowed(application *Application, appID string) (bool, error) {
	for _, item := range application.Providers {
		provider, err := GetProvider(util.GetId("admin", item.Name))
		if err != nil {
			return false, fmt.Errorf("read member application provider: %w", err)
		}
		if provider != nil && ((provider.Type == "WeChatMiniProgram" && provider.ClientId == appID) ||
			(provider.Type == "WeChat" && (provider.ClientId == appID || provider.ClientId2 == appID))) {
			return true, nil
		}
	}
	return false, nil
}

func GetMemberIdentity(application *Application, subject, appID string) (*MemberIdentity, error) {
	user, err := GetUserByUserId(application.Organization, subject)
	if err != nil || user == nil {
		return nil, err
	}
	result := &MemberIdentity{Subject: user.Id, Organization: user.Owner, AppId: appID}
	if appID != "" {
		exact := "user_id = ? AND app_id = ?"
		if ormer.driverName == "mysql" {
			exact = "BINARY user_id = ? AND BINARY app_id = ?"
		}
		var links []WechatIdentity
		if err = ormer.Engine.Where("owner = ? AND "+exact, user.Owner, subject, appID).Find(&links); err != nil {
			return nil, fmt.Errorf("read verified app identity: %w", err)
		}
		if len(links) > 1 {
			return nil, fmt.Errorf("ambiguous verified app identity")
		}
		if len(links) == 1 {
			result.OpenId = links[0].OpenId
		}
	}
	return result, nil
}
