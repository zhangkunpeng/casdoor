package object

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/casdoor/casdoor/util"
)

type MemberDirectoryItem struct {
	Subject      string `json:"subject"`
	Organization string `json:"organization"`
	Nickname     string `json:"nickname"`
	PhoneMask    string `json:"phoneMask"`
}

func GetMemberDirectory(application *Application, subjects []string) ([]MemberDirectoryItem, error) {
	if len(subjects) == 0 || len(subjects) > 100 {
		return nil, ErrMemberInvalid
	}
	result := make([]MemberDirectoryItem, 0, len(subjects))
	seen := make(map[string]bool, len(subjects))
	for _, subject := range subjects {
		if subject == "" || len(subject) > 255 || !utf8.ValidString(subject) ||
			strings.ContainsRune(subject, '\x00') || seen[subject] {
			return nil, ErrMemberInvalid
		}
		seen[subject] = true
		user, err := GetUserByUserId(application.Organization, subject)
		if err != nil {
			return nil, fmt.Errorf("read member directory: %w", err)
		}
		if user != nil && !user.IsDeleted {
			result = append(result, MemberDirectoryItem{Subject: user.Id, Organization: user.Owner,
				Nickname: user.DisplayName, PhoneMask: util.GetMaskedPhone(user.Phone)})
		}
	}
	return result, nil
}

func SearchMemberDirectory(application *Application, keyword string, nickname, phone bool) ([]string, error) {
	if len(keyword) > 200 || !utf8.ValidString(keyword) || strings.ContainsRune(keyword, '\x00') || !nickname && !phone {
		return nil, ErrMemberInvalid
	}
	columns := make([]string, 0, 2)
	arguments := []interface{}{application.Organization, false}
	pattern := "%" + strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(keyword) + "%"
	if nickname {
		columns = append(columns, "display_name LIKE ? ESCAPE '!'")
		arguments = append(arguments, pattern)
	}
	if phone {
		columns = append(columns, "phone LIKE ? ESCAPE '!'")
		arguments = append(arguments, pattern)
	}
	users := make([]User, 0)
	if err := ormer.Engine.Cols("id").Where("owner = ? AND is_deleted = ? AND ("+
		strings.Join(columns, " OR ")+")", arguments...).OrderBy("id").Limit(5001).Find(&users); err != nil {
		return nil, fmt.Errorf("search member directory: %w", err)
	}
	if len(users) > 5000 {
		return nil, ErrMemberInvalid
	}
	result := make([]string, 0, len(users))
	for _, user := range users {
		result = append(result, user.Id)
	}
	return result, nil
}
