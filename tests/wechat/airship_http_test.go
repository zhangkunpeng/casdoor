package wechat_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/controllers"
	"github.com/casdoor/casdoor/object"
)

type airshipFaceFixture struct {
	Issuer, CA, ClientID, ClientSecret, Subject, AssetID, Digest, Phase string
	Revision                                                            uint64
}

func TestAirshipMemberFaceHTTPInterop(t *testing.T) {
	repository := os.Getenv("AIRSHIP_MEMBER_INTEROP_REPO")
	if repository == "" {
		t.Skip("requires Airship worktree and isolated Device dependencies")
	}
	initializeProbe(t, true)
	web.Router("/api/login/oauth/member-face-profile", &controllers.ApiController{}, "POST:MemberFaceProfile")
	web.Router("/api/login/oauth/member-face-asset", &controllers.ApiController{}, "POST:MemberFaceAsset")
	owner := fmt.Sprintf("wx-device-%d", time.Now().UnixNano())
	app := createProbeApplication(t, owner, "device", owner+"-wx")
	app.MemberApiScopes = []string{"face:read"}
	if _, err := object.UpdateApplication(app.GetId(), app, true, "en", nil); err != nil {
		t.Fatal("isolated Device reader scope update failed")
	}
	var err error
	app, err = object.GetApplication(app.GetId())
	if err != nil || app == nil {
		t.Fatal("isolated Device application readback failed")
	}
	subject := verifiedSubject(t, app, miniToken(t, app, "new-test-code").AccessToken)
	user, err := object.GetUserByUserId(owner, subject)
	if err != nil || user == nil {
		t.Fatal("isolated Device subject readback failed")
	}
	server := httptest.NewTLSServer(web.BeeApp.Handlers)
	defer server.Close()
	fixture := airshipFaceFixture{Issuer: server.URL,
		CA:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})),
		ClientID: app.ClientId, ClientSecret: app.ClientSecret, Subject: subject}
	directory := t.TempDir()
	run := func(phase string, profile *object.MemberFaceProfile, photo []byte) {
		t.Helper()
		fixture.AssetID, fixture.Revision, fixture.Phase = profile.AssetId, profile.Revision, phase
		digest := sha256.Sum256(photo)
		fixture.Digest = hex.EncodeToString(digest[:])
		content, err := json.Marshal(fixture)
		file := filepath.Join(directory, "face-fixture.json")
		if err != nil || os.WriteFile(file, content, 0o600) != nil {
			t.Fatal("protected Device fixture write failed")
		}
		command := exec.Command("go", "test", "-p", "4", "./services/device/tests/integration",
			"-run", "^TestCasdoorOriginalHTTPInterop$", "-count=1", "-v")
		command.Dir = repository
		command.Env = append(os.Environ(), "AIRSHIP_CASDOOR_FACE_FIXTURE="+file)
		output, err := command.CombinedOutput()
		if err != nil || strings.Contains(string(output), "--- SKIP:") ||
			!strings.Contains(string(output), "--- PASS: TestCasdoorOriginalHTTPInterop") {
			for _, line := range strings.Split(string(output), "\n") {
				if strings.Contains(line, "casdoor_http_interop_test.go:") || strings.Contains(line, "undefined:") {
					t.Log(line)
				}
			}
			t.Fatalf("actual Casdoor to Device HTTPS integration failed: phase=%s", phase)
		}
		t.Logf("phase=%s actual Casdoor original and Device proxy passed", phase)
	}
	firstPhoto := facePhoto(t, 90)
	first, err := object.ChangeMemberFace(user, "first", 0, "replace", firstPhoto)
	if err != nil {
		t.Fatal("official face creation failed")
	}
	run("current", first, firstPhoto)
	fixture.ClientSecret = "invalid-isolated-credential"
	run("denied", first, nil)
	fixture.ClientSecret = app.ClientSecret
	secondPhoto := facePhoto(t, 180)
	second, err := object.ChangeMemberFace(user, "second", 1, "replace", secondPhoto)
	if err != nil {
		t.Fatal("official face replacement failed")
	}
	run("stale", first, nil)
	run("current", second, secondPhoto)
	if _, err := object.ChangeMemberFace(user, "delete", 2, "delete", nil); err != nil {
		t.Fatal("official cloud face deletion failed")
	}
	run("deleted", second, nil)
	stored, err := object.GetMemberFaceProfile(owner, subject)
	if err != nil || stored.Enabled || stored.Revision != 3 {
		t.Fatal("final face deletion readback failed")
	}
}
