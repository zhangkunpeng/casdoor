package object

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/casdoor/casdoor/idp"
)

func wechatAppIdentity(info *idp.UserInfo) (string, string, error) {
	var appID, openID string
	for key, value := range info.Extra {
		if strings.HasPrefix(key, "wechat_openid_") && value != "" {
			if openID != "" {
				return "", "", fmt.Errorf("ambiguous WeChat app identity")
			}
			appID, openID = strings.TrimPrefix(key, "wechat_openid_"), value
		}
	}
	if appID == "" || openID == "" {
		return "", "", fmt.Errorf("missing verified WeChat app OpenID")
	}
	return appID, openID, nil
}

func nativeWechatBindings(user *User) (map[string]string, error) {
	bindings := map[string]string{}
	if extra := user.Properties["oauth_WeChat_extra"]; extra != "" {
		if err := json.Unmarshal([]byte(extra), &bindings); err != nil {
			return nil, fmt.Errorf("decode native WeChat bindings: %w", err)
		}
	}
	if bindings == nil {
		return nil, fmt.Errorf("invalid native WeChat bindings")
	}
	return bindings, nil
}

func FindWechatUser(owner string, info *idp.UserInfo) (*User, error) {
	appID, openID, err := wechatAppIdentity(info)
	if err != nil {
		return nil, err
	}
	openBinding, err := json.Marshal(map[string]string{idp.BuildWechatOpenIdKey(appID): openID})
	if err != nil {
		return nil, err
	}
	// MySQL JSON string comparisons preserve the case of both AppID and OpenID.
	extra := "JSON_UNQUOTE(JSON_EXTRACT(NULLIF(properties, ''), '$.oauth_WeChat_extra'))"
	predicate := "BINARY wechat = ? OR JSON_CONTAINS(" + extra + ", ?) = 1"
	args := []interface{}{owner, info.Id, string(openBinding)}
	if union := info.Extra["wechat_unionid"]; union != "" {
		unionBinding, err := json.Marshal(map[string]string{"wechat_unionid": union})
		if err != nil {
			return nil, err
		}
		predicate += " OR JSON_CONTAINS(" + extra + ", ?) = 1"
		args = append(args, string(unionBinding))
	}
	var matches []*User
	if err := ormer.Engine.Where("BINARY owner = ? AND ("+predicate+")", args...).Find(&matches); err != nil {
		return nil, fmt.Errorf("find native WeChat identity: %w", err)
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("WeChat identity conflict")
	}
	if len(matches) == 0 {
		return nil, nil
	}
	user := matches[0]
	bindings, err := nativeWechatBindings(user)
	if err != nil {
		return nil, err
	}
	if union := info.Extra["wechat_unionid"]; union != "" &&
		bindings["wechat_unionid"] != "" && bindings["wechat_unionid"] != union {
		return nil, fmt.Errorf("WeChat UnionID conflict")
	}
	return user, nil
}

func SetWechatUserIdentity(user *User, info *idp.UserInfo) error {
	appID, openID, err := wechatAppIdentity(info)
	if err != nil {
		return err
	}
	found, err := FindWechatUser(user.Owner, info)
	if err != nil {
		return err
	}
	if found != nil && found.Name != user.Name {
		return fmt.Errorf("WeChat identity already belongs to another user")
	}
	bindings, err := nativeWechatBindings(user)
	if err != nil {
		return err
	}
	bindings[idp.BuildWechatOpenIdKey(appID)] = openID
	if union := info.Extra["wechat_unionid"]; union != "" {
		if old := bindings["wechat_unionid"]; old != "" && old != union {
			return fmt.Errorf("WeChat UnionID conflict")
		}
		bindings["wechat_unionid"] = union
	}
	extra, err := json.Marshal(bindings)
	if err != nil {
		return fmt.Errorf("encode native WeChat bindings: %w", err)
	}
	setUserProperty(user, "oauth_WeChat_extra", string(extra))
	if union := bindings["wechat_unionid"]; union != "" {
		user.WeChat = union
		setUserProperty(user, UserPropertiesWechatUnionId, union)
	} else {
		user.WeChat = info.Id
	}
	return nil
}
