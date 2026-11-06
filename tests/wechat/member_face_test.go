package wechat_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/casdoor/casdoor/object"
)

func TestWechatMemberFaceUsesNativeFaceIds(t *testing.T) {
	initializeProbe(t, true)
	app := createProbeApplication(t, fmt.Sprintf("wx-face-%d", time.Now().UnixNano()), "mini", "face-mini")
	session := miniToken(t, app, "new-test-code")
	subject := verifiedSubject(t, app, session.AccessToken)
	user, err := object.GetUserByUserId(app.Organization, subject)
	if err != nil || user == nil {
		t.Fatal("native face subject read failed")
	}

	user.FaceIds = []*object.FaceId{{
		Name:       "xueda-member-face:1:operation-digest",
		FaceIdData: []float64{0.1, 0.2, 0.3},
	}}
	if _, err := object.UpdateUser(user.GetId(), user, []string{"face_ids"}, true); err != nil {
		t.Fatal("native FaceIds update failed")
	}

	stored, err := object.GetUserByUserId(app.Organization, subject)
	if err != nil || stored == nil || len(stored.FaceIds) != 1 {
		t.Fatal("native FaceIds readback failed")
	}
	if stored.FaceIds[0].Name != user.FaceIds[0].Name {
		t.Fatal("native FaceIds identity changed during persistence")
	}
}
