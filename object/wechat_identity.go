package object

import (
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/casdoor/casdoor/idp"
)

type WechatIdentity struct {
	Owner  string `xorm:"varchar(100) pk"`
	Key    string `xorm:"varchar(64) pk"`
	UserId string `xorm:"varchar(255) notnull"`
	AppId  string `xorm:"varchar(100)"`
	OpenId string `xorm:"varchar(255)"`
}

// LockWechatOrganization serializes all WeChat registration paths across processes on the shared MySQL database.
func LockWechatOrganization(owner string) (func(), error) {
	return lockCasdoorResource("wechat:" + owner)
}

func lockCasdoorResource(resource string) (func(), error) {
	if ormer.driverName != "mysql" {
		return nil, fmt.Errorf("WeChat registration locking requires MySQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	conn, err := ormer.Engine.DB().DB.Conn(ctx)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256([]byte(ormer.dbName + ":" + resource))
	key := hex.EncodeToString(hash[:])
	var acquired int
	if err = conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, 30)", key).Scan(&acquired); err != nil || acquired != 1 {
		_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		conn.Close()
		if err != nil {
			return nil, fmt.Errorf("acquire WeChat registration lock: %w", err)
		}
		return nil, fmt.Errorf("WeChat registration lock timed out")
	}
	return func() {
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer releaseCancel()
		var released int
		if err := conn.QueryRowContext(releaseCtx, "SELECT RELEASE_LOCK(?)", key).Scan(&released); err != nil || released != 1 {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
		_ = conn.Close()
	}, nil
}

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

func wechatIdentityKeys(info *idp.UserInfo) ([]string, error) {
	appID, openID, err := wechatAppIdentity(info)
	if err != nil {
		return nil, err
	}
	keys := []string{idp.BuildWechatOpenIdKey(appID) + ":" + openID}
	if union := info.Extra["wechat_unionid"]; union != "" {
		keys = append(keys, "union:"+union)
	}
	for i, key := range keys {
		hash := sha256.Sum256([]byte(key))
		keys[i] = hex.EncodeToString(hash[:])
	}
	return keys, nil
}

func FindWechatUser(owner string, info *idp.UserInfo) (*User, error) {
	keys, err := wechatIdentityKeys(info)
	if err != nil {
		return nil, err
	}
	var found *User
	for _, key := range keys {
		link := WechatIdentity{Owner: owner, Key: key}
		exists, err := ormer.Engine.Get(&link)
		if err != nil {
			return nil, err
		}
		if !exists {
			continue
		}
		user, err := GetUserByUserId(owner, link.UserId)
		if err != nil {
			return nil, err
		}
		if user == nil {
			return nil, fmt.Errorf("WeChat identity points to missing user")
		}
		if found != nil && found.Id != user.Id {
			return nil, fmt.Errorf("WeChat identity conflict")
		}
		found = user
	}
	var matches []*User
	err = ormer.Engine.Where("owner = ? AND BINARY wechat = ?", owner, info.Id).Find(&matches)
	if len(matches) > 1 {
		return nil, fmt.Errorf("ambiguous WeChat identity")
	}
	var canonical *User
	if len(matches) == 1 {
		canonical = matches[0]
	}
	if err != nil {
		return nil, err
	}
	if canonical != nil {
		if found != nil && canonical.Id != found.Id {
			return nil, fmt.Errorf("WeChat identity conflict")
		}
		found = canonical
	}
	if found != nil && info.Extra["wechat_unionid"] != "" {
		old := found.Properties[UserPropertiesWechatUnionId]
		if old != "" && old != info.Extra["wechat_unionid"] {
			return nil, fmt.Errorf("WeChat UnionID conflict")
		}
	}
	return found, nil
}

func bindWechatIdentity(user *User, info *idp.UserInfo) error {
	keys, err := wechatIdentityKeys(info)
	if err != nil {
		return err
	}
	appID, openID, err := wechatAppIdentity(info)
	if err != nil {
		return err
	}
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err = session.Begin(); err != nil {
		return err
	}
	for index, key := range keys {
		link := WechatIdentity{Owner: user.Owner, Key: key}
		exists, err := session.Get(&link)
		if err != nil {
			return err
		}
		if exists && link.UserId != user.Id {
			return fmt.Errorf("WeChat identity already belongs to another user")
		}
		if !exists {
			link.UserId = user.Id
			if index == 0 {
				link.AppId, link.OpenId = appID, openID
			}
			if _, err = session.Insert(&link); err != nil {
				return err
			}
		} else if index == 0 {
			link.AppId, link.OpenId = appID, openID
			if _, err = session.Where("owner = ? AND "+quoteColumn("key")+" = ?", link.Owner, link.Key).
				Cols("app_id", "open_id").Update(&link); err != nil {
				return err
			}
		}
	}
	if err = session.Commit(); err != nil {
		return err
	}
	if user.Properties == nil {
		user.Properties = map[string]string{}
	}
	if union := info.Extra["wechat_unionid"]; union != "" {
		user.WeChat = union
		user.Properties[UserPropertiesWechatUnionId] = union
	} else if user.WeChat == "" {
		user.WeChat = info.Id
	}
	return nil
}
