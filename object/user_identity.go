package object

import (
	"errors"
	"strings"
	"unicode/utf8"
)

var ErrUserSubjectImmutable = errors.New("user subject is immutable")

func validateUserSubject(subject string) error {
	if subject == "" || len(subject) > 255 || !utf8.ValidString(subject) || strings.ContainsRune(subject, '\x00') {
		return errors.New("invalid user subject")
	}
	return nil
}
