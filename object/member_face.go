package object

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"

	"github.com/casdoor/casdoor/util"
)

const MemberFaceMaxBytes = 8 * 1024 * 1024

type MemberFaceProfile struct {
	Key      string `xorm:"varchar(64) pk" json:"-"`
	Revision uint64 `json:"revision"`
	AssetId  string `xorm:"varchar(100)" json:"assetId"`
	Enabled  bool   `json:"enabled"`
}

type MemberFaceAsset struct {
	Id          string `xorm:"varchar(100) pk" json:"-"`
	ProfileKey  string `xorm:"varchar(64) index" json:"-"`
	ContentType string `xorm:"varchar(32)" json:"-"`
	Content     []byte `xorm:"mediumblob" json:"-"`
}

type MemberFaceOperation struct {
	Key    string `xorm:"varchar(64) pk" json:"-"`
	Digest string `xorm:"varchar(64)" json:"-"`
	Result string `xorm:"text" json:"-"`
}

func GetMemberFaceProfile(owner, subject string) (*MemberFaceProfile, error) {
	profile := MemberFaceProfile{Key: memberOperationKey("face", owner, subject)}
	_, err := ormer.Engine.Get(&profile)
	if err != nil {
		return nil, fmt.Errorf("read current face profile: %w", err)
	}
	return &profile, nil
}

func ChangeMemberFace(user *User, operationID string, expected uint64, action string, content []byte) (*MemberFaceProfile, error) {
	if operationID == "" || len(operationID) > 100 || (action != "replace" && action != "delete") {
		return nil, ErrMemberInvalid
	}
	contentType := ""
	if action == "replace" {
		if len(content) == 0 || len(content) > MemberFaceMaxBytes {
			return nil, ErrMemberInvalid
		}
		config, format, err := image.DecodeConfig(bytes.NewReader(content))
		if err != nil || (format != "png" && format != "jpeg") ||
			config.Width <= 0 || config.Height <= 0 || config.Width > 4096 || config.Height > 4096 {
			return nil, ErrMemberInvalid
		}
		contentType = "image/" + format
	}
	profileKey := memberOperationKey("face", user.Owner, user.Id)
	operation := MemberFaceOperation{Key: memberOperationKey(profileKey, operationID)}
	hash := sha256.Sum256(content)
	digest := memberOperationKey(action, fmt.Sprint(expected), hex.EncodeToString(hash[:]))
	release, err := lockCasdoorResource("member-face:" + profileKey)
	if err != nil {
		return nil, fmt.Errorf("lock face operation: %w", err)
	}
	defer release()
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return nil, fmt.Errorf("begin face change: %w", err)
	}
	defer session.Rollback()
	current := User{Owner: user.Owner, Name: user.Name}
	exists, err := session.ForUpdate().Get(&current)
	if err != nil {
		return nil, fmt.Errorf("lock member for face change: %w", err)
	}
	if !exists || current.Id != user.Id || current.IsForbidden || current.IsDeleted {
		return nil, ErrMemberUnauthenticated
	}
	exists, err = session.Get(&operation)
	if err != nil {
		return nil, fmt.Errorf("read face operation: %w", err)
	}
	if exists {
		if operation.Digest != digest {
			return nil, ErrMemberConflict
		}
		var result MemberFaceProfile
		if err := json.Unmarshal([]byte(operation.Result), &result); err != nil {
			return nil, fmt.Errorf("decode persisted face result: %w", err)
		}
		return &result, nil
	}
	profile := MemberFaceProfile{Key: profileKey}
	exists, err = session.Get(&profile)
	if err != nil {
		return nil, fmt.Errorf("read face revision: %w", err)
	}
	if profile.Revision != expected || profile.Revision == ^uint64(0) {
		return nil, ErrMemberConflict
	}
	// Cloud deletion removes original bytes, independently of installed device templates.
	if _, err := session.Where("profile_key = ?", profileKey).Delete(&MemberFaceAsset{}); err != nil {
		return nil, fmt.Errorf("delete previous cloud face assets: %w", err)
	}
	profile.Revision++
	profile.AssetId, profile.Enabled = "", false
	if action == "replace" {
		asset := MemberFaceAsset{Id: util.GenerateAuthorizationCode(), ProfileKey: profileKey,
			ContentType: contentType, Content: content}
		if _, err := session.Insert(&asset); err != nil {
			return nil, fmt.Errorf("persist private face asset: %w", err)
		}
		profile.AssetId, profile.Enabled = asset.Id, true
	}
	if exists {
		_, err = session.ID(profileKey).AllCols().Update(&profile)
	} else {
		_, err = session.Insert(&profile)
	}
	if err != nil {
		return nil, fmt.Errorf("persist current face profile: %w", err)
	}
	result, err := json.Marshal(&profile)
	if err != nil {
		return nil, fmt.Errorf("encode immutable face result: %w", err)
	}
	operation.Digest, operation.Result = digest, string(result)
	if _, err := session.Insert(&operation); err != nil {
		return nil, fmt.Errorf("persist face operation: %w", err)
	}
	if err := session.Commit(); err != nil {
		return nil, fmt.Errorf("commit face change: %w", err)
	}
	return &profile, nil
}

func GetMemberFaceAsset(application *Application, subject, assetID string, revision uint64) (*MemberFaceAsset, error) {
	user, err := GetUserByUserId(application.Organization, subject)
	if err != nil {
		return nil, fmt.Errorf("read face subject: %w", err)
	}
	if user == nil || user.IsForbidden || user.IsDeleted {
		return nil, ErrMemberNotFound
	}
	profile, err := GetMemberFaceProfile(user.Owner, user.Id)
	if err != nil {
		return nil, err
	}
	if !profile.Enabled || profile.AssetId != assetID || profile.Revision != revision {
		return nil, ErrMemberNotFound
	}
	asset := MemberFaceAsset{Id: assetID, ProfileKey: profile.Key}
	exists, err := ormer.Engine.Get(&asset)
	if err != nil {
		return nil, fmt.Errorf("read protected face image: %w", err)
	}
	if !exists {
		return nil, ErrMemberNotFound
	}
	return &asset, nil
}
