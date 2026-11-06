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
	return BindMemberPhoneWithProof(application, accessToken, appID, code, MemberAccessProof{})
}

func BindMemberPhoneWithProof(application *Application, accessToken, appID, code string, proof MemberAccessProof) error {
	if code == "" || len(code) > 1024 {
		return ErrMemberInvalid
	}
	token, user, err := resolvePhoneUserAccess(application, accessToken, proof)
	if err != nil {
		return err
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

	// Serialize bindings before taking user locks so two accounts cannot claim the same phone.
	organization := Organization{}
	found, err := getForUpdate(session, &organization, "admin", user.Owner)
	if err != nil {
		return fmt.Errorf("lock phone binding organization: %w", err)
	}
	if !found {
		return ErrMemberUnauthenticated
	}
	currentToken := Token{}
	found, err = getForUpdate(session, &currentToken, token.Owner, token.Name)
	if err != nil {
		return fmt.Errorf("lock phone binding token: %w", err)
	}
	if !found {
		return ErrMemberUnauthenticated
	}
	if err := checkCurrentMemberPhoneToken(application, token, &currentToken); err != nil {
		return err
	}
	current, err := lockUserForMutation(session, user)
	if err != nil {
		if errors.Is(err, errUserMutationUnavailable) {
			return errors.Join(ErrMemberUnauthenticated, err)
		}
		return err
	}
	updated := *current
	updated.Phone, updated.CountryCode = phone, country
	msg, err := checkUserPhone(current, &updated, "en", session)
	if err != nil {
		return fmt.Errorf("check trusted member phone: %w", err)
	}
	if msg != "" {
		return fmt.Errorf("%w: %s", ErrMemberInvalid, msg)
	}
	columns, err := prepareUserUpdate(session, &updated, []string{"phone", "country_code", "updated_time"})
	if err != nil {
		return fmt.Errorf("prepare trusted member phone: %w", err)
	}
	if err := checkCurrentMemberPhoneToken(application, token, &currentToken); err != nil {
		return err
	}
	affected, err := updateUserInSession(session, current.GetId(), &updated, columns)
	if err != nil {
		return fmt.Errorf("update trusted member phone; authorize a fresh code: %w", err)
	}
	if affected == 0 && (current.Phone != updated.Phone || current.CountryCode != updated.CountryCode) {
		return fmt.Errorf("phone binding user is no longer available")
	}
	if err := session.Commit(); err != nil {
		return fmt.Errorf("commit phone binding; authorize a fresh code: %w", err)
	}
	return nil
}
