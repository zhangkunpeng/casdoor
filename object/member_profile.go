package object

import (
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

type MemberProfileChange struct {
	Nickname *string
	Avatar   *string
}

func UpdateMemberProfile(user *User, change MemberProfileChange) error {
	if change.Nickname == nil && change.Avatar == nil {
		return ErrMemberInvalid
	}
	if change.Nickname != nil && (len(*change.Nickname) > 200 || !utf8.ValidString(*change.Nickname) ||
		strings.TrimSpace(*change.Nickname) == "" || strings.ContainsAny(*change.Nickname, "\x00\r\n")) {
		return ErrMemberInvalid
	}
	if change.Avatar != nil && *change.Avatar != "" {
		avatar, err := url.Parse(*change.Avatar)
		if err != nil || len(*change.Avatar) > 2048 || avatar.Scheme != "https" ||
			avatar.Hostname() == "" || avatar.User != nil || avatar.Fragment != "" ||
			strings.TrimSpace(*change.Avatar) != *change.Avatar {
			return ErrMemberInvalid
		}
	}
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return fmt.Errorf("begin member profile change: %w", err)
	}
	defer session.Rollback()
	current := User{Owner: user.Owner, Name: user.Name}
	found, err := session.ForUpdate().Get(&current)
	if err != nil {
		return fmt.Errorf("lock member for profile change: %w", err)
	}
	if !found || current.Id != user.Id || current.IsForbidden || current.IsDeleted {
		return ErrMemberUnauthenticated
	}
	columns := make([]string, 0, 2)
	if change.Nickname != nil {
		current.DisplayName = *change.Nickname
		columns = append(columns, "display_name")
	}
	if change.Avatar != nil {
		current.Avatar = *change.Avatar
		columns = append(columns, "avatar")
	}
	if _, err := session.Where("owner = ? AND name = ?", current.Owner, current.Name).
		Cols(columns...).Update(&current); err != nil {
		return fmt.Errorf("update member profile: %w", err)
	}
	if err := session.Commit(); err != nil {
		return fmt.Errorf("commit member profile change: %w", err)
	}
	return nil
}
