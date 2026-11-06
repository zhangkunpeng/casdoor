package wechat_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/object"
)

func TestWechatMemberFaceUsesNativeFaceIds(t *testing.T) {
	initializeProbe(t, true)
	registerNativeMemberAPI()
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
	server := httptest.NewServer(web.BeeApp.Handlers)
	defer server.Close()
	status, fields := nativeMemberRequest(t, server.URL, "/api/update-user", app, session.AccessToken,
		url.Values{"id": {user.GetId()}, "columns": {"faceIds"}}, map[string]any{
			"owner": user.Owner, "name": user.Name, "id": user.Id, "faceIds": user.FaceIds,
		})
	if status != http.StatusOK || fields == nil {
		t.Fatal("native self FaceIds update failed")
	}

	stored, err := object.GetUserByUserId(app.Organization, subject)
	if err != nil || stored == nil || len(stored.FaceIds) != 1 {
		t.Fatal("native FaceIds readback failed")
	}
	if stored.FaceIds[0].Name != user.FaceIds[0].Name {
		t.Fatal("native FaceIds identity changed during persistence")
	}
}
