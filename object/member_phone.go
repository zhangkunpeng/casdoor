package object

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/casdoor/casdoor/idp"
	"github.com/casdoor/casdoor/util"
)

func memberWechatProvider(application *Application, appID string) (*Provider, error) {
	for _, item := range application.Providers {
		provider, err := GetProvider("admin/" + item.Name)
		if err != nil {
			return nil, fmt.Errorf("read member WeChat provider: %w", err)
		}
		if provider != nil && provider.Type == "WeChatMiniProgram" && provider.ClientId == appID {
			return provider, nil
		}
	}
	return nil, ErrMemberAppDenied
}

func BindMemberPhone(application *Application, user *User, appID, code string) error {
	if code == "" || len(code) > 1024 {
		return ErrMemberInvalid
	}
	provider, err := memberWechatProvider(application, appID)
	if err != nil {
		return err
	}
	mpIdp := idp.NewWeChatMiniProgramIdProvider(provider.ClientId, provider.ClientSecret)
	mpIdp.SetHttpClient(&http.Client{Timeout: 10 * time.Second})
	e164, err := mpIdp.GetPhoneNumber(code)
	if err != nil {
		return fmt.Errorf("verify member phone; authorize a fresh code: %w", err)
	}
	phone, country := util.ParseE164Phone(e164)
	if len(phone) < 6 || len(phone) > 20 || len(country) != 2 ||
		strings.Trim(phone, "0123456789") != "" {
		return fmt.Errorf("invalid trusted phone response")
	}
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return fmt.Errorf("begin phone binding: %w", err)
	}
	defer session.Rollback()
	current := User{Owner: user.Owner, Name: user.Name}
	found, err := session.ForUpdate().Get(&current)
	if err != nil {
		return fmt.Errorf("lock member for phone binding: %w", err)
	}
	if !found || current.Id != user.Id || current.IsForbidden || current.IsDeleted {
		return ErrMemberUnauthenticated
	}
	current.Phone, current.CountryCode = phone, country
	if _, err := session.Where("owner = ? AND name = ?", current.Owner, current.Name).
		Cols("phone", "country_code").Update(&current); err != nil {
		return fmt.Errorf("update trusted member phone; authorize a fresh code: %w", err)
	}
	if err := session.Commit(); err != nil {
		return fmt.Errorf("commit phone binding; authorize a fresh code: %w", err)
	}
	return nil
}
