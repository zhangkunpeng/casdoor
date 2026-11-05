package object

import (
	"fmt"

	"github.com/casdoor/casdoor/util"
)

type MemberPermission struct {
	Owner        string   `json:"owner"`
	ResourceType string   `json:"resourceType"`
	Resources    []string `json:"resources"`
	Actions      []string `json:"actions"`
	Effect       string   `json:"effect"`
	IsEnabled    bool     `json:"isEnabled"`
	ExpireTime   string   `json:"expireTime"`
}

type MemberIdentity struct {
	Subject      string             `json:"subject"`
	Organization string             `json:"organization"`
	Nickname     string             `json:"nickname"`
	Avatar       string             `json:"avatar"`
	Phone        string             `json:"phone"`
	CountryCode  string             `json:"countryCode"`
	IsForbidden  bool               `json:"isForbidden"`
	IsDeleted    bool               `json:"isDeleted"`
	Roles        []string           `json:"roles"`
	Permissions  []MemberPermission `json:"permissions"`
	AppId        string             `json:"appId,omitempty"`
	OpenId       string             `json:"openId,omitempty"`
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
	if err = ExtendUserWithRolesAndPermissions(user); err != nil {
		return nil, fmt.Errorf("read current member permissions: %w", err)
	}
	result := &MemberIdentity{Subject: user.Id, Organization: user.Owner, Nickname: user.DisplayName,
		Avatar: user.Avatar, Phone: user.Phone, CountryCode: user.CountryCode,
		IsForbidden: user.IsForbidden, IsDeleted: user.IsDeleted,
		Roles: []string{}, Permissions: []MemberPermission{}, AppId: appID}
	for _, role := range user.Roles {
		result.Roles = append(result.Roles, role.Name)
	}
	for _, permission := range user.Permissions {
		result.Permissions = append(result.Permissions, MemberPermission{Owner: permission.Owner,
			ResourceType: permission.ResourceType, Resources: permission.Resources, Actions: permission.Actions,
			Effect: permission.Effect, IsEnabled: permission.IsEnabled, ExpireTime: permission.ExpireTime})
	}
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
