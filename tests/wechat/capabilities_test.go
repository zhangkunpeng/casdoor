package wechat_test

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/proxy"
	"github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
)

func probeRoot() string {
	_, source, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(source), "../.."))
}

var initializeProbeOnce sync.Once

func initializeProbe(t *testing.T, create bool) {
	t.Helper()
	dsn := os.Getenv("CASDOOR_WECHAT_TEST_DSN")
	if dsn == "" {
		t.Skip("requires isolated MySQL CASDOOR_WECHAT_TEST_DSN")
	}
	if !isolatedProbeDSN(dsn) {
		t.Fatal("CASDOOR_WECHAT_TEST_DSN requires loopback TCP and no database name")
	}
	t.Setenv("driverName", "mysql")
	t.Setenv("dataSourceName", dsn)
	t.Setenv("dbName", "casdoor_probe")
	t.Setenv("origin", "http://127.0.0.1:8000")
	t.Setenv("socks5Proxy", "")
	t.Setenv("staticBaseUrl", "")
	initializeProbeOnce.Do(func() {
		web.BConfig.CopyRequestBody = true
		web.BConfig.WebConfig.Session.SessionOn = true
		web.BConfig.WebConfig.Session.SessionProvider = "memory"
		web.TestBeegoInit(probeRoot())
		object.InitAdapter()
		if create {
			object.CreateTables()
			object.InitDb()
		}
		object.InitUserManager()
	})
	officialUnion := &atomic.Bool{}
	officialUnion.Store(true)
	base := http.DefaultTransport
	http.DefaultTransport = wechatTransport{base, officialUnion}
	t.Cleanup(func() { http.DefaultTransport = base })
	proxy.InitHttpClient()
}

func isolatedProbeDSN(dsn string) bool {
	config, err := mysql.ParseDSN(dsn)
	if err != nil || config.Net != "tcp" || config.DBName != "" {
		return false
	}
	host, port, err := net.SplitHostPort(config.Addr)
	if err != nil || port == "" {
		return false
	}
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

func TestProbeDSNIsolation(t *testing.T) {
	for _, scenario := range []struct {
		dsn  string
		safe bool
	}{
		{"probe:test-only@tcp(127.0.0.1:33060)/", true},
		{"probe:test-only@tcp(localhost:33060)/", true},
		{"probe:test-only@tcp([::1]:33060)/", true},
		{"probe:test-only@tcp(192.0.2.1:3306)/", false},
		{"probe:test-only@tcp(127.0.0.1:33060)/shared", false},
		{"probe:test-only@unix(/tmp/mysql.sock)/", false},
		{"invalid DSN", false},
	} {
		if isolatedProbeDSN(scenario.dsn) != scenario.safe {
			t.Fatal("probe DSN isolation classification mismatch")
		}
	}
}

func createProbeApplication(t *testing.T, owner, suffix, appID string) *object.Application {
	t.Helper()
	org, err := object.GetOrganization("admin/" + owner)
	if err != nil {
		t.Fatal(err)
	}
	if org == nil {
		if _, err := object.AddOrganization(&object.Organization{
			Owner: "admin", Name: owner, PasswordType: "bcrypt", DefaultTokenFormat: "JWT",
		}); err != nil {
			t.Fatal(err)
		}
	}
	p := &object.Provider{Owner: "admin", Name: owner + "-" + suffix,
		Category: "OAuth", Type: "WeChatMiniProgram", ClientId: appID, ClientSecret: "test-only"}
	if _, err := object.AddProvider(p); err != nil {
		t.Fatal(err)
	}
	app := &object.Application{Owner: "admin", Name: p.Name, Organization: owner,
		ClientId: p.Name + "-client", ClientSecret: "test-only", EnableSignUp: true,
		TokenFormat: "JWT", GrantTypes: []string{"token", "refresh_token"},
		Cert: "cert-built-in", ExpireInHours: 0.25,
		Providers:   []*object.ProviderItem{{Name: p.Name, CanSignUp: true, CanSignIn: true, Provider: p}},
		SignupItems: []*object.SignupItem{{Name: "ID", Rule: "Random"}}}
	if _, err := object.AddApplication(app, "en"); err != nil {
		t.Fatal(err)
	}
	app, err = object.GetApplication(app.GetId())
	if err != nil {
		t.Fatal(err)
	}
	return app
}

func miniToken(t *testing.T, app *object.Application, code string) *object.Token {
	t.Helper()
	token, tokenError, err := object.GetWechatMiniProgramToken(app, code, "127.0.0.1:8000", "", "", "en")
	if err != nil || tokenError != nil || token == nil {
		t.Fatalf("mini login failed: implementationError=%t tokenError=%t", err != nil, tokenError != nil)
	}
	return token
}

func verifiedSubject(t *testing.T, app *object.Application, raw string) string {
	t.Helper()
	cert, err := object.GetCert("admin/cert-built-in")
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cert.Certificate))
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return key, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(app.ClientId),
		jwt.WithIssuer("http://127.0.0.1:8000"), jwt.WithExpirationRequired())
	if err != nil {
		t.Fatal("issued token signature or trust validation failed")
	}
	subject, err := token.Claims.GetSubject()
	if err != nil || subject == "" {
		t.Fatal("issued token has no subject")
	}
	return subject
}

func probeDatabase(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("mysql", os.Getenv("CASDOOR_WECHAT_TEST_DSN")+"casdoor_probe")
	if err != nil {
		t.Fatal("isolated database connection failed")
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func probeAccountCounts(t *testing.T, owner string) (int, int) {
	t.Helper()
	db := probeDatabase(t)
	var users, links int
	if err := db.QueryRow("SELECT COUNT(*) FROM `user` WHERE owner = ?", owner).Scan(&users); err != nil {
		t.Fatal("account count read failed")
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM wechat_identity WHERE owner = ?", owner).Scan(&links); err != nil {
		t.Fatal("identity count read failed")
	}
	return users, links
}

type processResult struct {
	AccessToken     string
	RefreshRejected bool
}

func runProbeProcesses(t *testing.T, app *object.Application, refreshToken, credentialAppID string) []processResult {
	t.Helper()
	resultDir := t.TempDir()
	ready := filepath.Join(resultDir, "start")
	refreshPath := ""
	if refreshToken != "" {
		refreshPath = filepath.Join(resultDir, "refresh")
		if err := os.WriteFile(refreshPath, []byte(refreshToken), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestWechatProcessHelper$", "-test.v")
			cmd.Dir = filepath.Join(probeRoot(), "tests/wechat")
			cmd.Env = append(os.Environ(), "XUEDA_PROBE_APP="+app.GetId(),
				"XUEDA_PROBE_BARRIER="+ready, "XUEDA_PROBE_RESULT="+filepath.Join(resultDir, fmt.Sprint(index)),
				"XUEDA_PROBE_READY="+filepath.Join(resultDir, fmt.Sprintf("ready-%d", index)),
				"XUEDA_PROBE_REFRESH_PATH="+refreshPath, "XUEDA_PROBE_WECHAT_APPID="+credentialAppID)
			if output, err := cmd.CombinedOutput(); err != nil {
				for _, line := range strings.Split(string(output), "\n") {
					if strings.Contains(line, "capabilities_test.go:") || strings.HasPrefix(line, "panic:") {
						errs <- fmt.Errorf("process %d: %s", index, line)
						return
					}
				}
				errs <- fmt.Errorf("process %d failed; output length=%d", index, len(output))
			}
		}(i)
	}
	deadline := time.Now().Add(30 * time.Second)
	for i := 0; i < 2; i++ {
		for {
			if _, err := os.Stat(filepath.Join(resultDir, fmt.Sprintf("ready-%d", i))); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("child process did not reach login barrier")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if err := os.WriteFile(ready, []byte("start"), 0o600); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var results []processResult
	for i := 0; i < 2; i++ {
		content, err := os.ReadFile(filepath.Join(resultDir, fmt.Sprint(i)))
		if err != nil {
			t.Fatal(err)
		}
		var result processResult
		if err := json.Unmarshal(content, &result); err != nil {
			t.Fatal(err)
		}
		results = append(results, result)
	}
	return results
}

func TestWechatIndependentProcesses(t *testing.T) {
	initializeProbe(t, true)
	owner := fmt.Sprintf("wx-process-%d", time.Now().UnixNano())
	app := createProbeApplication(t, owner, "mini", "process-mini")
	results := runProbeProcesses(t, app, "", "")
	first := verifiedSubject(t, app, results[0].AccessToken)
	second := verifiedSubject(t, app, results[1].AccessToken)
	users, links := probeAccountCounts(t, owner)
	if first != second || users != 1 || links != 2 {
		t.Fatalf("concurrent account invariant failed: sameSubject=%t users=%d links=%d",
			first == second, users, links)
	}
}

func TestWechatProcessHelper(t *testing.T) {
	appID := os.Getenv("XUEDA_PROBE_APP")
	if appID == "" {
		t.Skip("child-process helper")
	}
	initializeProbe(t, false)
	app, err := object.GetApplication(appID)
	if err != nil || app == nil {
		t.Fatal("probe application not found")
	}
	if err := os.WriteFile(os.Getenv("XUEDA_PROBE_READY"), []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(os.Getenv("XUEDA_PROBE_BARRIER")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("process barrier timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
	var result processResult
	if credentialAppID := os.Getenv("XUEDA_PROBE_WECHAT_APPID"); credentialAppID != "" {
		credential, err := object.GetMemberWechatCredential(app, credentialAppID)
		if err != nil {
			t.Fatal("independent WeChat credential request failed")
		}
		result.AccessToken = credential.AccessToken
	} else if refreshPath := os.Getenv("XUEDA_PROBE_REFRESH_PATH"); refreshPath != "" {
		raw, err := os.ReadFile(refreshPath)
		if err != nil {
			t.Fatal("protected refresh input unavailable")
		}
		response, err := object.RefreshToken(app, "refresh_token", string(raw), "",
			app.ClientId, app.ClientSecret, "", "127.0.0.1:8000", "")
		if err != nil {
			t.Fatal("independent refresh dependency failure")
		}
		switch value := response.(type) {
		case *object.TokenWrapper:
			result.AccessToken = value.AccessToken
		case *object.TokenError:
			if value.Error != object.InvalidGrant {
				t.Fatal("unexpected independent refresh rejection")
			}
			result.RefreshRejected = true
		default:
			t.Fatal("unexpected independent refresh result")
		}
	} else {
		result.AccessToken = miniToken(t, app, "new-test-code").AccessToken
	}
	content, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("XUEDA_PROBE_RESULT"), content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestWechatAppIDAndAccountIsolation(t *testing.T) {
	initializeProbe(t, true)
	t.Run("different-wechat", func(t *testing.T) {
		owner := fmt.Sprintf("wx-person-%d", time.Now().UnixNano())
		app := createProbeApplication(t, owner, "mini", "app-a")
		first := verifiedSubject(t, app, miniToken(t, app, "new-test-code").AccessToken)
		second := verifiedSubject(t, app, miniToken(t, app, "different-wechat").AccessToken)
		users, links := probeAccountCounts(t, owner)
		if first == second || users != 2 || links != 4 {
			t.Fatalf("different people merged: sameSubject=%t users=%d links=%d", first == second, users, links)
		}
	})
	t.Run("different-appid-without-union", func(t *testing.T) {
		owner := fmt.Sprintf("wx-app-%d", time.Now().UnixNano())
		a := createProbeApplication(t, owner, "a", "app-a")
		b := createProbeApplication(t, owner, "b", "app-b")
		first := verifiedSubject(t, a, miniToken(t, a, "no-union").AccessToken)
		second := verifiedSubject(t, b, miniToken(t, b, "no-union").AccessToken)
		users, links := probeAccountCounts(t, owner)
		if first == second || users != 2 || links != 2 {
			t.Fatalf("unrelated application identities merged: sameSubject=%t users=%d links=%d", first == second, users, links)
		}
	})
	t.Run("rename-keeps-wechat-login-subject", func(t *testing.T) {
		owner := fmt.Sprintf("wx-rename-%d", time.Now().UnixNano())
		app := createProbeApplication(t, owner, "mini", "app-a")
		first := verifiedSubject(t, app, miniToken(t, app, "new-test-code").AccessToken)
		user, err := object.GetUserByUserId(owner, first)
		if err != nil || user == nil {
			t.Fatal("persisted user not found")
		}
		oldID := user.GetId()
		user.Name = "renamed-member"
		if _, err := object.UpdateUser(oldID, user, []string{"name"}, true); err != nil {
			t.Fatal("rename failed")
		}
		second := verifiedSubject(t, app, miniToken(t, app, "new-test-code").AccessToken)
		if first != second || strings.TrimSpace(second) == "" {
			t.Fatal("rename changed WeChat subject")
		}
	})
}
