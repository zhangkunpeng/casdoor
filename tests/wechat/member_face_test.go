package wechat_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/controllers"
	"github.com/casdoor/casdoor/object"
)

type faceResult struct {
	Revision uint64 `json:"revision"`
	AssetID  string `json:"assetId"`
	Enabled  bool   `json:"enabled"`
}

func faceMutation(t *testing.T, server string, app *object.Application, token, operation string, revision uint64, action string, photo []byte) (int, faceResult) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range map[string]string{"access_token": token, "operation_id": operation,
		"expected_revision": strconv.FormatUint(revision, 10), "action": action, "consent": "true"} {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatal("face form encoding failed")
		}
	}
	if photo != nil {
		part, err := writer.CreateFormFile("photo", "face.png")
		if err != nil {
			t.Fatal("face image form failed")
		}
		if _, err := part.Write(photo); err != nil {
			t.Fatal("face image write failed")
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal("face form close failed")
	}
	request, err := http.NewRequest(http.MethodPost, server+"/api/login/oauth/member-face", &body)
	if err != nil {
		t.Fatal("face request creation failed")
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.SetBasicAuth(app.ClientId, app.ClientSecret)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal("face request failed")
	}
	defer response.Body.Close()
	var result faceResult
	_ = json.NewDecoder(response.Body).Decode(&result)
	return response.StatusCode, result
}

func facePhoto(t *testing.T, shade uint8) []byte {
	t.Helper()
	picture := image.NewRGBA(image.Rect(0, 0, 16, 16))
	picture.Set(0, 0, color.RGBA{R: shade, A: 255})
	var body bytes.Buffer
	if err := png.Encode(&body, picture); err != nil {
		t.Fatal("synthetic face fixture creation failed")
	}
	return body.Bytes()
}

func faceAssetRequest(t *testing.T, server string, app *object.Application, subject string, face faceResult) (int, []byte) {
	t.Helper()
	values := url.Values{"subject": {subject}, "asset_id": {face.AssetID}, "revision": {strconv.FormatUint(face.Revision, 10)}}
	request, _ := http.NewRequest(http.MethodPost, server+"/api/login/oauth/member-face-asset", strings.NewReader(values.Encode()))
	request.SetBasicAuth(app.ClientId, app.ClientSecret)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal("protected face download failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal("protected face response read failed")
	}
	return response.StatusCode, body
}

func TestWechatMemberFace(t *testing.T) {
	initializeProbe(t, true)
	web.Router("/api/login/oauth/member-face", &controllers.ApiController{}, "POST:MemberFace")
	web.Router("/api/login/oauth/member-face-asset", &controllers.ApiController{}, "POST:MemberFaceAsset")
	app := createProbeApplication(t, fmt.Sprintf("wx-face-%d", time.Now().UnixNano()), "mini", "face-mini")
	app.MemberApiScopes = []string{"face:read", "face:write"}
	if _, err := object.UpdateApplication(app.GetId(), app, true, "en", nil); err != nil {
		t.Fatal("face scope update failed")
	}
	var err error
	app, err = object.GetApplication(app.GetId())
	if err != nil || app == nil {
		t.Fatal("face application persistence read failed")
	}
	session := miniToken(t, app, "new-test-code")
	subject := verifiedSubject(t, app, session.AccessToken)
	server := httptest.NewServer(web.BeeApp.Handlers)
	defer server.Close()
	firstPhoto := facePhoto(t, 100)
	status, first := faceMutation(t, server.URL, app, session.AccessToken, "first", 0, "replace", firstPhoto)
	if status != http.StatusOK || !first.Enabled || first.Revision != 1 || first.AssetID == "" {
		t.Fatalf("versioned private face upload failed: status=%d", status)
	}
	status, body := faceAssetRequest(t, server.URL, app, subject, first)
	if status != http.StatusOK || !bytes.Equal(body, firstPhoto) {
		t.Fatal("Device service did not receive the authorized original image")
	}
	status, duplicate := faceMutation(t, server.URL, app, session.AccessToken, "first", 0, "replace", firstPhoto)
	if status != http.StatusOK || duplicate != first {
		t.Fatal("duplicate upload changed the immutable asset or revision")
	}
	secondPhoto := facePhoto(t, 200)
	status, second := faceMutation(t, server.URL, app, session.AccessToken, "second", 1, "replace", secondPhoto)
	if status != http.StatusOK || second.Revision != 2 || second.AssetID == first.AssetID {
		t.Fatal("replacement did not advance the face version")
	}
	if status, _ := faceAssetRequest(t, server.URL, app, subject, first); status != http.StatusNotFound {
		t.Fatal("retired face version remained downloadable")
	}
	status, _ = faceMutation(t, server.URL, app, session.AccessToken, "late", 1, "replace", firstPhoto)
	if status != http.StatusConflict {
		t.Fatal("late photo update overwrote the current version")
	}
	status, duplicate = faceMutation(t, server.URL, app, session.AccessToken, "first", 0, "replace", firstPhoto)
	if status != http.StatusOK || duplicate != first {
		t.Fatal("late duplicate did not retain its original immutable result")
	}
	if status, body := faceAssetRequest(t, server.URL, app, subject, second); status != http.StatusOK || !bytes.Equal(body, secondPhoto) {
		t.Fatal("late duplicate reverted the current photo")
	}
	db := probeDatabase(t)
	if _, err := db.Exec("CREATE TRIGGER xueda_face_failure BEFORE INSERT ON member_face_operation FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'injected face write failure'"); err != nil {
		t.Fatal("face failure trigger creation failed")
	}
	t.Cleanup(func() { db.Exec("DROP TRIGGER IF EXISTS xueda_face_failure") })
	if status, _ := faceMutation(t, server.URL, app, session.AccessToken, "failed-delete", 2, "delete", nil); status != http.StatusServiceUnavailable {
		t.Fatal("partial face change reported success")
	}
	if status, body := faceAssetRequest(t, server.URL, app, subject, second); status != http.StatusOK || !bytes.Equal(body, secondPhoto) {
		t.Fatal("failed face change did not roll back profile and original bytes")
	}
	if _, err := db.Exec("DROP TRIGGER xueda_face_failure"); err != nil {
		t.Fatal("face failure trigger cleanup failed")
	}
	other := verifiedSubject(t, app, miniToken(t, app, "different-wechat").AccessToken)
	if status, _ := faceAssetRequest(t, server.URL, app, other, second); status != http.StatusNotFound {
		t.Fatal("another subject read a private face asset")
	}
	denied := createProbeApplication(t, app.Organization, "denied", "face-denied")
	if status, _ := faceAssetRequest(t, server.URL, denied, subject, second); status != http.StatusForbidden {
		t.Fatal("application without face scope read a private image")
	}
	status, deleted := faceMutation(t, server.URL, app, session.AccessToken, "delete", 2, "delete", nil)
	if status != http.StatusOK || deleted.Enabled || deleted.Revision != 3 || deleted.AssetID != "" {
		t.Fatal("cloud deletion did not disable and advance the profile")
	}
	if status, _ := faceAssetRequest(t, server.URL, app, subject, second); status != http.StatusNotFound {
		t.Fatal("cloud-deleted image remained downloadable")
	}
	if status, result := faceMutation(t, server.URL, app, session.AccessToken, "delete", 2, "delete", nil); status != http.StatusOK || result != deleted {
		t.Fatal("duplicate cloud deletion changed the result")
	}
}
