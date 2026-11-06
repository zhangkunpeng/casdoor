package object

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/casdoor/casdoor/idp"
	"github.com/casdoor/casdoor/util"
)

var (
	ErrMemberUnauthenticated = errors.New("phone binding access token is inactive")
	ErrMemberAppDenied       = errors.New("phone binding application is not allowed")
	ErrMemberInvalid         = errors.New("invalid phone binding")
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

func BindMemberPhone(application *Application, accessToken, appID, code string) error {
	if code == "" || len(code) > 1024 {
		return ErrMemberInvalid
	}
	token, err := GetTokenByAccessToken(accessToken)
	if err != nil {
		return fmt.Errorf("read phone binding access token: %w", err)
	}
	if token == nil || token.ExpiresIn <= 0 || token.User == "" || token.Owner != application.Owner ||
		token.Application != application.Name || token.Organization != application.Organization {
		return ErrMemberUnauthenticated
	}
	if expired, _ := util.IsTokenExpired(token.CreatedTime, token.ExpiresIn); expired {
		return ErrMemberUnauthenticated
	}
	user, err := GetUser(util.GetId(token.Organization, token.User))
	if err != nil {
		return fmt.Errorf("read phone binding user: %w", err)
	}
	if user == nil || user.IsForbidden || user.IsDeleted {
		return ErrMemberUnauthenticated
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
	user.Phone, user.CountryCode = phone, country
	updated, err := UpdateUser(user.GetId(), user, []string{"phone", "country_code"}, true)
	if err != nil {
		return fmt.Errorf("update trusted member phone; authorize a fresh code: %w", err)
	}
	if !updated {
		return fmt.Errorf("phone binding user is no longer available")
	}
	return nil
}
