package object

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type MemberPhoneOperation struct {
	Key         string `xorm:"varchar(64) pk" json:"-"`
	Digest      string `xorm:"varchar(64)" json:"-"`
	Phone       string `xorm:"varchar(32)" json:"-"`
	CountryCode string `xorm:"varchar(8)" json:"-"`
	Completed   bool   `json:"-"`
}

func memberOperationKey(parts ...string) string {
	body, _ := json.Marshal(parts)
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:])
}

func BindMemberPhone(application *Application, user *User, appID, operationID, code string) error {
	if operationID == "" || len(operationID) > 100 || code == "" || len(code) > 1024 {
		return ErrMemberInvalid
	}
	provider, err := memberWechatProvider(application, appID)
	if err != nil {
		return err
	}
	if provider.Type != "WeChatMiniProgram" {
		return ErrMemberAppDenied
	}
	key := memberOperationKey("phone", user.Owner, user.Id, appID, operationID)
	digest := memberOperationKey(code)
	release, err := lockCasdoorResource("member-phone:" + key)
	if err != nil {
		return fmt.Errorf("lock phone operation: %w", err)
	}
	defer release()
	operation := MemberPhoneOperation{Key: key}
	exists, err := ormer.Engine.Get(&operation)
	if err != nil {
		return fmt.Errorf("read phone operation: %w", err)
	}
	if exists && operation.Digest != digest {
		return ErrMemberConflict
	}
	if operation.Completed {
		return nil
	}
	if !exists {
		client := &http.Client{Timeout: 10 * time.Second}
		credential, err := getWechatCredential(client, provider)
		if err != nil {
			return err
		}
		operation.Digest = digest
		if err := consumeMemberPhoneCode(client, credential.AccessToken, code, &operation); err != nil {
			return err
		}
		// Retain the trusted proof before changing the profile so a failed write can retry.
		if _, err = ormer.Engine.Insert(&operation); err != nil {
			return fmt.Errorf("persist trusted phone proof; authorize a fresh code: %w", err)
		}
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
	current.Phone, current.CountryCode = operation.Phone, operation.CountryCode
	if _, err := session.Where("owner = ? AND name = ?", current.Owner, current.Name).
		Cols("phone", "country_code").Update(&current); err != nil {
		return fmt.Errorf("update trusted member phone: %w", err)
	}
	operation.Completed = true
	if _, err := session.ID(key).Cols("completed").Update(&operation); err != nil {
		return fmt.Errorf("complete phone binding: %w", err)
	}
	if err := session.Commit(); err != nil {
		return fmt.Errorf("commit phone binding: %w", err)
	}
	return nil
}

func consumeMemberPhoneCode(client *http.Client, token, code string, operation *MemberPhoneOperation) error {
	body, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		return fmt.Errorf("encode phone authorization: %w", err)
	}
	response, err := client.Post("https://api.weixin.qq.com/wxa/business/getuserphonenumber?"+
		url.Values{"access_token": {token}}.Encode(), "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("consume phone authorization: %w", err)
	}
	defer response.Body.Close()
	var result struct {
		ErrCode   int `json:"errcode"`
		PhoneInfo struct {
			PurePhoneNumber string `json:"purePhoneNumber"`
			CountryCode     string `json:"countryCode"`
		} `json:"phone_info"`
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("phone authorization HTTP status: %d", response.StatusCode)
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode phone authorization: %w", err)
	}
	if result.ErrCode != 0 {
		return ErrMemberInvalid
	}
	phone, country := result.PhoneInfo.PurePhoneNumber, result.PhoneInfo.CountryCode
	if len(phone) < 6 || len(phone) > 20 || len(country) == 0 || len(country) > 4 ||
		strings.Trim(phone+country, "0123456789") != "" {
		return fmt.Errorf("invalid trusted phone response")
	}
	operation.Phone, operation.CountryCode = phone, country
	return nil
}
