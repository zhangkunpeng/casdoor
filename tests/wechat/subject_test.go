package wechat_test

import (
	"fmt"
	"strings"
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
	if _, err := object.AddUser(&duplicate, "en"); err != nil {
		t.Fatal("deleted subject could not be assigned by native account creation")
	}
	restored, err := object.GetUserByUserId(owner, subject)
	if err != nil || restored == nil || restored.Name != duplicate.Name {
		t.Fatal("replacement subject was not persisted")
	}
}

func TestWechatSubjectValidationUsesNativeUserWrites(t *testing.T) {
	initializeProbe(t, true)
	owner := fmt.Sprintf("wx-subject-format-%d", time.Now().UnixNano())
	createProbeApplication(t, owner, "mini", "subject-format-mini")
	for i, subject := range []string{"bad\x00subject", string([]byte{0xff}), strings.Repeat("界", 86)} {
		user := &object.User{Owner: owner, Name: fmt.Sprintf("invalid-%d", i), Id: subject}
		if _, err := object.AddUser(user, "en"); err == nil {
			t.Fatal("invalid subject accepted by native account insertion")
		}
		if _, err := object.AddUsers([]*object.User{user}); err == nil {
			t.Fatal("invalid subject accepted by native batch insertion")
		}
	}
}

func TestWechatNativeSchema(t *testing.T) {
	initializeProbe(t, true)
	db := probeDatabase(t)
	var customTables int
	if err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.tables
		WHERE table_schema = DATABASE() AND table_name IN
		('user_subject', 'wechat_identity', 'member_phone_operation')`).Scan(&customTables); err != nil {
		t.Fatal(err)
	}
	if customTables != 0 {
		t.Fatalf("custom identity tables=%d, want 0", customTables)
	}
}

func TestWechatDeletionUsesNativeAccountLifecycle(t *testing.T) {
	initializeProbe(t, true)
	owner := fmt.Sprintf("wx-deletion-%d", time.Now().UnixNano())
	app := createProbeApplication(t, owner, "mini", "deletion-mini")
	app.SignupItems = []*object.SignupItem{{Name: "ID", Rule: "Incremental"}}
	if _, err := object.UpdateApplication(app.GetId(), app, true, "en", nil); err != nil {
		t.Fatal(err)
	}
	app, err := object.GetApplication(app.GetId())
	if err != nil || app == nil {
		t.Fatal("incremental application read failed")
	}
	first := miniToken(t, app, "new-test-code")
	subject := verifiedSubject(t, app, first.AccessToken)
	user, err := object.GetUserByUserId(owner, subject)
	if err != nil || user == nil {
		t.Fatal("registered member not found")
	}
	if _, err := object.DeleteUser(user); err != nil {
		t.Fatal(err)
	}
	second := miniToken(t, app, "new-test-code")
	if verifiedSubject(t, app, second.AccessToken) != subject {
		t.Fatal("native incremental ID generation could not reuse the deleted ID")
	}
}
