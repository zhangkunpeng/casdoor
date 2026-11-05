package wechat_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/controllers"
	"github.com/casdoor/casdoor/object"
	"github.com/golang-jwt/jwt/v5"
)

type scopedWechatTransport struct {
	base  http.RoundTripper
	scope string
}

func (r scopedWechatTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := r.base.RoundTrip(request)
	if err != nil || request.URL.Host != "api.weixin.qq.com" || request.URL.Path != "/sns/jscode2session" {
		return response, err
	}
	defer response.Body.Close()
	var identity map[string]any
	if err := json.NewDecoder(response.Body).Decode(&identity); err != nil {
		return nil, fmt.Errorf("decode isolated WeChat identity: %w", err)
	}
	for _, field := range []string{"openid", "unionid"} {
		if value, ok := identity[field].(string); ok && value != "" {
			identity[field] = value + "-" + r.scope
		}
	}
	content, err := json.Marshal(identity)
	if err != nil {
		return nil, err
	}
	response.Body = io.NopCloser(bytes.NewReader(content))
	response.ContentLength = int64(len(content))
	return response, nil
}

type xuedaHTTPFixture struct {
	Endpoint, Issuer, Organization, Application, ClientID, ClientSecret, AppID         string
	Subject, AccessToken, IDToken, OtherClientID, OtherSecret, OtherAccessToken        string
	Phase, FreshAccessToken, FreshRefreshToken                                         string
	AdminApplication, AdminClientID, AdminClientSecret, AdminAccessToken, AdminSubject string
}

func TestXuedaMemberHTTPInterop(t *testing.T) {
	repository := os.Getenv("XUEDA_MEMBER_INTEROP_REPO")
	if repository == "" {
		t.Skip("requires Xueda worktree for the real HTTP interoperability test")
	}
	initializeProbe(t, true)
	t.Setenv("origin", "https://casdoor.xueda.me")
	name := fmt.Sprintf("xueda-interop-%d", time.Now().UnixNano())
	base := http.DefaultTransport
	http.DefaultTransport = phoneTransport{base: scopedWechatTransport{base: base, scope: name}, calls: &atomic.Int32{}, used: &sync.Map{}}
	t.Cleanup(func() { http.DefaultTransport = base })
	web.Router("/api/login/oauth/access_token", &controllers.ApiController{}, "POST:GetOAuthToken")
	web.Router("/api/login/oauth/refresh_token", &controllers.ApiController{}, "POST:RefreshToken")
	web.Router("/api/login/oauth/revoke", &controllers.ApiController{}, "POST:RevokeOAuthToken")
	web.Router("/api/login/oauth/introspect", &controllers.ApiController{}, "POST:IntrospectToken")
	web.Router("/api/login/oauth/member-identity", &controllers.ApiController{}, "POST:MemberIdentity")
	web.Router("/api/login/oauth/member-profile", &controllers.ApiController{}, "POST:MemberProfile")
	web.Router("/api/login/oauth/member-phone", &controllers.ApiController{}, "POST:MemberPhone")
	web.Router("/api/login/oauth/member-face", &controllers.ApiController{}, "POST:MemberFace")
	web.Router("/api/login/oauth/member-face-profile", &controllers.ApiController{}, "POST:MemberFaceProfile")
	web.Router("/api/login/oauth/member-face-asset", &controllers.ApiController{}, "POST:MemberFaceAsset")
	web.Router("/.well-known/:application/openid-configuration", &controllers.RootController{}, "GET:GetOidcDiscoveryByApplication")
	web.Router("/.well-known/:application/jwks", &controllers.RootController{}, "GET:GetJwksByApplication")
	app := createProbeApplication(t, "airship", name, name+"-wx")
	app.MemberApiScopes = []string{"profile:read", "profile:write", "phone:write", "face:read", "face:write"}
	if _, err := object.UpdateApplication(app.GetId(), app, true, "en", nil); err != nil {
		t.Fatal("interop application scopes update failed")
	}
	var err error
	app, err = object.GetApplication(app.GetId())
	if err != nil || app == nil {
		t.Fatal("interop application persistence read failed")
	}
	other := createProbeApplication(t, "airship", name+"-other", name+"-other-wx")
	token, otherToken := miniToken(t, app, "new-test-code"), miniToken(t, other, "new-test-code")
	adminApp := createProbeApplication(t, "airship", name+"-admin", name+"-admin-wx")
	adminApp.MemberApiScopes = []string{"profile:read"}
	if _, err := object.UpdateApplication(adminApp.GetId(), adminApp, true, "en", nil); err != nil {
		t.Fatal("isolated administrator application scopes update failed")
	}
	adminApp, err = object.GetApplication(adminApp.GetId())
	if err != nil || adminApp == nil {
		t.Fatal("isolated administrator application persistence read failed")
	}
	adminToken := miniToken(t, adminApp, "different-wechat")
	cert, err := object.GetCert("admin/cert-built-in")
	if err != nil {
		t.Fatal("actual signing certificate read failed")
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cert.Certificate))
	if err != nil {
		t.Fatal("actual public key parse failed")
	}
	verified, err := jwt.Parse(token.AccessToken, func(*jwt.Token) (any, error) { return key, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(app.ClientId),
		jwt.WithIssuer("https://casdoor.xueda.me"), jwt.WithExpirationRequired())
	if err != nil {
		t.Fatal("actual issued member token failed trust verification")
	}
	subject, err := verified.Claims.GetSubject()
	if err != nil || subject == "" {
		t.Fatal("actual issued subject is missing")
	}
	server := httptest.NewServer(web.BeeApp.Handlers)
	defer server.Close()
	fixture := xuedaHTTPFixture{Endpoint: server.URL, Issuer: "https://casdoor.xueda.me", Organization: app.Organization,
		Application: app.Name, ClientID: app.ClientId, ClientSecret: app.ClientSecret, AppID: name + "-wx",
		Subject: subject, AccessToken: token.AccessToken, IDToken: token.IdToken,
		OtherClientID: other.ClientId, OtherSecret: other.ClientSecret, OtherAccessToken: otherToken.AccessToken,
		AdminApplication: adminApp.Name, AdminClientID: adminApp.ClientId, AdminClientSecret: adminApp.ClientSecret,
		AdminAccessToken: adminToken.AccessToken}
	adminVerified, err := jwt.Parse(adminToken.AccessToken, func(*jwt.Token) (any, error) { return key, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(adminApp.ClientId),
		jwt.WithIssuer("https://casdoor.xueda.me"), jwt.WithExpirationRequired())
	if err != nil {
		t.Fatal("actual issued administrator token failed trust verification")
	}
	fixture.AdminSubject, err = adminVerified.Claims.GetSubject()
	if err != nil || fixture.AdminSubject == "" || fixture.AdminSubject == fixture.Subject {
		t.Fatal("isolated administrator subject is missing or aliases the member")
	}
	directory := t.TempDir()
	runPhase := func(phase string) {
		t.Helper()
		fixture.Phase = phase
		body, err := json.Marshal(fixture)
		if err != nil || os.WriteFile(filepath.Join(directory, "fixture.json"), body, 0o600) != nil {
			t.Fatal("protected integration fixture write failed")
		}
		command := exec.Command("go", "test", "-p", "4", "-tags=integration",
			"./internal/infrastructure/bootstrap/wiring", "-run", "^TestCasdoorMemberHTTPIntegration$", "-count=1", "-v")
		command.Dir = repository
		command.Env = append(os.Environ(), "XUEDA_CASDOOR_HTTP_INTEGRATION=1",
			"XUEDA_CASDOOR_HTTP_FIXTURE="+filepath.Join(directory, "fixture.json"))
		output, err := command.CombinedOutput()
		if err != nil {
			for _, line := range strings.Split(string(output), "\n") {
				if strings.Contains(line, "casdoor_member_integration_test.go:") || strings.HasPrefix(line, "panic:") ||
					strings.Contains(line, "undefined:") {
					t.Log(line)
				}
			}
			t.Fatalf("Xueda real HTTP integration failed: phase=%s", phase)
		}
		if strings.Contains(string(output), "--- SKIP:") || !strings.Contains(string(output), "--- PASS: TestCasdoorMemberHTTPIntegration") {
			t.Fatal("Xueda HTTP integration did not actually execute")
		}
		t.Logf("phase=%s real signed Token/JWKS/online/profile API passed", phase)
	}
	runPhase("normal")
	db := probeDatabase(t)
	runPhase("admin-no-permission")
	adminUser, err := object.GetUserByUserId("airship", fixture.AdminSubject)
	if err != nil || adminUser == nil {
		t.Fatal("isolated administrator account persistence read failed")
	}
	adminPermission := &object.Permission{Owner: "admin", Name: name + "-access",
		Users: []string{adminUser.GetId()}, Model: "built-in/user-model-built-in",
		ResourceType: "Custom", Resources: []string{"xueda-admin/*"},
		Actions: []string{"access"}, Effect: "Allow", IsEnabled: true}
	if _, err := object.AddPermission(adminPermission); err != nil {
		t.Fatal("isolated administrator access permission create failed")
	}
	t.Cleanup(func() { object.DeletePermission(adminPermission) })
	runPhase("admin-access")
	directoryPermission := &object.Permission{Owner: "admin", Name: name + "-directory",
		Users: []string{adminUser.GetId()}, Model: "built-in/user-model-built-in",
		ResourceType: "Custom", Resources: []string{"xueda-admin/people"},
		Actions: []string{"read"}, Effect: "Allow", IsEnabled: true}
	if _, err := object.AddPermission(directoryPermission); err != nil {
		t.Fatal("isolated directory permission create failed")
	}
	t.Cleanup(func() { object.DeletePermission(directoryPermission) })
	runPhase("admin-directory")
	if _, err := object.DeletePermission(directoryPermission); err != nil {
		t.Fatal("isolated directory permission removal failed")
	}
	runPhase("admin-directory-removed")
	if _, err := object.DeletePermission(adminPermission); err != nil {
		t.Fatal("isolated administrator permission removal failed")
	}
	runPhase("admin-permission-removed")
	if _, err := object.AddPermission(adminPermission); err != nil {
		t.Fatal("isolated administrator permission restoration failed")
	}
	if _, err := db.Exec("CREATE TRIGGER xueda_admin_revoke_failure BEFORE UPDATE ON `token` FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'injected administrator revoke failure'"); err != nil {
		t.Fatal("administrator revoke failure trigger creation failed")
	}
	t.Cleanup(func() { db.Exec("DROP TRIGGER IF EXISTS xueda_admin_revoke_failure") })
	runPhase("admin-revoke-failure")
	if _, err := db.Exec("DROP TRIGGER xueda_admin_revoke_failure"); err != nil {
		t.Fatal("administrator revoke failure trigger cleanup failed")
	}
	adminUser.IsForbidden = true
	if _, err := object.UpdateUser(adminUser.GetId(), adminUser, []string{"is_forbidden"}, true); err != nil {
		t.Fatal("isolated administrator disable failed")
	}
	runPhase("admin-disabled")
	adminUser.IsForbidden = false
	if _, err := object.UpdateUser(adminUser.GetId(), adminUser, []string{"is_forbidden"}, true); err != nil {
		t.Fatal("isolated administrator enable failed")
	}
	runPhase("admin-revoked")
	fixture.AdminAccessToken = miniToken(t, adminApp, "different-wechat").AccessToken
	runPhase("admin-enabled")
	if _, err := db.Exec("CREATE TRIGGER xueda_face_failure BEFORE INSERT ON member_face_operation FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'injected face operation failure'"); err != nil {
		t.Fatal("face failure trigger creation failed")
	}
	t.Cleanup(func() { db.Exec("DROP TRIGGER IF EXISTS xueda_face_failure") })
	runPhase("face-delete-failure")
	if _, err := db.Exec("DROP TRIGGER xueda_face_failure"); err != nil {
		t.Fatal("face failure trigger cleanup failed")
	}
	runPhase("face-delete-retry")
	face, err := object.GetMemberFaceProfile("airship", subject)
	if err != nil || face.Revision != 3 || face.Enabled || face.AssetId != "" {
		t.Fatal("Xueda face deletion did not persist its original subject version")
	}
	failureSession := miniToken(t, app, "new-test-code")
	fixture.FreshAccessToken, fixture.FreshRefreshToken = failureSession.AccessToken, failureSession.RefreshToken
	if _, err := db.Exec("CREATE TRIGGER xueda_revoke_failure BEFORE UPDATE ON `token` FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'injected revocation write failure'"); err != nil {
		t.Fatal("revocation failure trigger creation failed")
	}
	t.Cleanup(func() { db.Exec("DROP TRIGGER IF EXISTS xueda_revoke_failure") })
	runPhase("revoke-failure")
	if _, err := db.Exec("DROP TRIGGER xueda_revoke_failure"); err != nil {
		t.Fatal("revocation failure trigger cleanup failed")
	}
	runPhase("revoke-retry")
	user, err := object.GetUserByUserId("airship", subject)
	if err != nil || user == nil || user.DisplayName != "互操作验证昵称" || user.Phone != "13800000000" {
		t.Fatal("Xueda mutation did not persist on the original Casdoor subject")
	}
	t.Cleanup(func() {
		user.IsForbidden = false
		if _, err := object.UpdateUser(user.GetId(), user, []string{"is_forbidden"}, true); err != nil {
			t.Error("isolated member state cleanup failed")
		}
	})
	role := &object.Role{Owner: "airship", Name: "xueda-member-restricted", IsEnabled: true, Users: []string{user.GetId()}}
	if _, err := object.AddRole(role); err != nil {
		t.Fatal("isolated restriction role create failed")
	}
	t.Cleanup(func() {
		if _, err := object.DeleteRole(role); err != nil {
			t.Error("isolated restriction role cleanup failed")
		}
	})
	runPhase("restricted")
	role.Users = nil
	if _, err := object.UpdateRole(role.GetId(), role, true, "en"); err != nil {
		t.Fatal("isolated restriction removal failed")
	}
	runPhase("restriction-removed")
	user.IsForbidden = true
	if _, err := object.UpdateUser(user.GetId(), user, []string{"is_forbidden"}, true); err != nil {
		t.Fatal("isolated member disable failed")
	}
	runPhase("disabled")
	user.IsForbidden = false
	if _, err := object.UpdateUser(user.GetId(), user, []string{"is_forbidden"}, true); err != nil {
		t.Fatal("isolated member enable failed")
	}
	fixture.FreshAccessToken = miniToken(t, app, "new-test-code").AccessToken
	runPhase("enabled")
}
