package wechat_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/casdoor/casdoor/object"
)

func TestWechatSubjectLifecycle(t *testing.T) {
	initializeProbe(t, true)
	owner := fmt.Sprintf("wx-subject-%d", time.Now().UnixNano())
	app := createProbeApplication(t, owner, "mini", "subject-mini")
	subject := verifiedSubject(t, app, miniToken(t, app, "new-test-code").AccessToken)
	user, err := object.GetUserByUserId(owner, subject)
	if err != nil || user == nil {
		t.Fatal("registered subject not found")
	}
	changed := *user
	changed.Id = "another-subject"
	if _, err := object.UpdateUser(user.GetId(), &changed, []string{"id"}, true); err == nil {
		t.Fatal("subject changed by profile update")
	}
	if _, err := object.UpdateUserForAllFields(user.GetId(), &changed); err == nil {
		t.Fatal("subject changed by full profile replacement")
	}
	duplicate := *user
	duplicate.Name = "duplicate-subject"
	if _, err := object.AddUser(&duplicate, "en"); err == nil {
		t.Fatal("duplicate subject assigned to another account")
	}
	if _, err := object.DeleteUser(user); err != nil {
		t.Fatal("account delete failed")
	}
	if _, err := object.AddUser(&duplicate, "en"); err == nil {
		t.Fatal("deleted subject assigned to a new account")
	}
	restored, err := object.GetUserByUserId(owner, subject)
	if err != nil || restored != nil {
		t.Fatal("deleted subject remained live")
	}
}
