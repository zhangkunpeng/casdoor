package object

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/xorm-io/core"
	"github.com/xorm-io/xorm"
)

var ErrUserSubjectImmutable = errors.New("user subject is immutable")
var ErrUserSubjectReserved = errors.New("user subject was already assigned")

type UserSubject struct {
	Owner string `xorm:"varchar(100) pk"`
	Key   string `xorm:"varchar(64) pk"`
}

func userSubjectReservation(user *User) (UserSubject, error) {
	if len(user.Id) == 0 || len(user.Id) > 255 || !utf8.ValidString(user.Id) || strings.ContainsRune(user.Id, '\x00') {
		return UserSubject{}, fmt.Errorf("invalid user subject")
	}
	hash := sha256.Sum256([]byte(user.Id))
	return UserSubject{Owner: user.Owner, Key: hex.EncodeToString(hash[:])}, nil
}

func insertSubjectUsers(users []*User) (int64, error) {
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return 0, fmt.Errorf("begin account creation: %w", err)
	}
	defer session.Rollback()
	for _, user := range users {
		reservation, err := userSubjectReservation(user)
		if err != nil {
			return 0, err
		}
		existing, err := GetUserByUserId(user.Owner, user.Id)
		if err != nil {
			return 0, fmt.Errorf("check assigned subject: %w", err)
		}
		if existing != nil {
			return 0, ErrUserSubjectReserved
		}
		exists, err := session.Exist(&UserSubject{Owner: reservation.Owner, Key: reservation.Key})
		if err != nil {
			return 0, fmt.Errorf("check reserved subject: %w", err)
		}
		if exists {
			return 0, ErrUserSubjectReserved
		}
		if _, err = session.Insert(&reservation); err != nil {
			return 0, fmt.Errorf("reserve subject: %w", errors.Join(ErrUserSubjectReserved, err))
		}
	}
	affected, err := session.Insert(users)
	if err != nil {
		return 0, fmt.Errorf("insert subject accounts: %w", err)
	}
	if err = session.Commit(); err != nil {
		return 0, fmt.Errorf("commit account creation: %w", err)
	}
	return affected, nil
}

func deleteSubjectUser(user *User) (int64, error) {
	reservation, err := userSubjectReservation(user)
	if err != nil {
		return 0, err
	}
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err = session.Begin(); err != nil {
		return 0, fmt.Errorf("begin account deletion: %w", err)
	}
	defer session.Rollback()
	current := User{Owner: user.Owner, Name: user.Name}
	exists, err := session.ForUpdate().Get(&current)
	if err != nil {
		return 0, fmt.Errorf("lock account to delete: %w", err)
	}
	if !exists {
		return 0, nil
	}
	if current.Id != user.Id {
		return 0, ErrUserSubjectImmutable
	}
	if err = retainUserSubject(session, reservation); err != nil {
		return 0, err
	}
	affected, err := session.ID(core.PK{user.Owner, user.Name}).Delete(&User{})
	if err != nil {
		return 0, fmt.Errorf("delete account: %w", err)
	}
	if err = session.Commit(); err != nil {
		return 0, fmt.Errorf("commit account deletion: %w", err)
	}
	return affected, nil
}

func retainUserSubject(session *xorm.Session, reservation UserSubject) error {
	exists, err := session.Exist(&UserSubject{Owner: reservation.Owner, Key: reservation.Key})
	if err != nil {
		return fmt.Errorf("check deleted subject reservation: %w", err)
	}
	if exists {
		return nil
	}
	if _, err = session.Insert(&reservation); err != nil {
		return fmt.Errorf("retain deleted subject: %w", err)
	}
	return nil
}
