package wechat_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/authz"
	"github.com/casdoor/casdoor/controllers"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/proxy"
	"github.com/casdoor/casdoor/routers"
	"github.com/go-sql-driver/mysql"
)

var initializeProbeOnce sync.Once

func initializeProbe(t *testing.T, create bool) {
	t.Helper()
	dsn := os.Getenv("CASDOOR_WECHAT_TEST_DSN")
	if dsn == "" {
		t.Skip("requires isolated MySQL CASDOOR_WECHAT_TEST_DSN")
	}
	config, err := mysql.ParseDSN(dsn)
	if err != nil || config.Net != "tcp" || config.DBName != "" {
		t.Fatal("test DSN must use loopback TCP without a database name")
	}
	host, _, err := net.SplitHostPort(config.Addr)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() {
		t.Fatal("test DSN must use loopback TCP")
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
		_, source, _, _ := runtime.Caller(0)
		web.TestBeegoInit(filepath.Clean(filepath.Join(filepath.Dir(source), "../..")))
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
	token, tokenError, err := object.GetWechatMiniProgramToken(app, code, "", false, "127.0.0.1:8000", "", "", "en")
	if err != nil || tokenError != nil || token == nil {
		t.Fatalf("mini login failed: %v / %v", err, tokenError)
	}
	return token
}

func verifiedSubject(t *testing.T, app *object.Application, raw string) string {
	t.Helper()
	claims, err := object.ParseJwtTokenByApplication(raw, app)
	if err != nil || claims.Subject == "" {
		t.Fatalf("invalid issued token: %v", err)
	}
	return claims.Subject
}

func probeDatabase(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("mysql", os.Getenv("CASDOOR_WECHAT_TEST_DSN")+"casdoor_probe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func probeAccountCount(t *testing.T, owner string) int {
	t.Helper()
	var users int
	if err := probeDatabase(t).QueryRow("SELECT COUNT(*) FROM `user` WHERE owner = ?", owner).Scan(&users); err != nil {
		t.Fatal(err)
	}
	return users
}

func TestWechatUsesNativeUserSchema(t *testing.T) {
	initializeProbe(t, true)
	typ := reflect.TypeOf(object.User{})
	for name, tag := range map[string]string{"Owner": "varchar(100) notnull pk", "Id": "varchar(100) index"} {
		field, _ := typ.FieldByName(name)
		if field.Tag.Get("xorm") != tag {
			t.Fatalf("%s schema changed", name)
		}
	}
	var dataType string
	var length, uniqueSubjects int
	db := probeDatabase(t)
	if err := db.QueryRow("SELECT data_type, character_maximum_length FROM information_schema.columns WHERE table_schema = 'casdoor_probe' AND table_name = 'user' AND column_name = 'id'").Scan(&dataType, &length); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = 'casdoor_probe' AND table_name = 'user' AND index_name LIKE '%subject%'").Scan(&uniqueSubjects); err != nil {
		t.Fatal(err)
	}
	if dataType != "varchar" || length != 100 || uniqueSubjects != 0 {
		t.Fatalf("unexpected native schema: %s(%d), subject indexes=%d", dataType, length, uniqueSubjects)
	}
}

func TestWechatWithoutUnionIDUsesNativeLookup(t *testing.T) {
	initializeProbe(t, true)
	owner := fmt.Sprintf("wx-native-%d", time.Now().UnixNano())
	a := createProbeApplication(t, owner, "a", "native-app-a")
	b := createProbeApplication(t, owner, "b", "native-app-b")
	first := verifiedSubject(t, a, miniToken(t, a, "no-union").AccessToken)
	second := verifiedSubject(t, b, miniToken(t, b, "no-union").AccessToken)
	user, err := object.GetUserByUserId(owner, first)
	if err != nil || user == nil {
		t.Fatalf("read native user: %v", err)
	}
	if first != second || probeAccountCount(t, owner) != 1 || user.WeChat != "mini-open" ||
		user.Name != "wechat-mini-open" || user.Properties[object.UserPropertiesWechatOpenId] != "mini-open" ||
		user.Properties[object.UserPropertiesWechatUnionId] != "" || user.Properties["oauth_WeChat_extra"] != "" {
		t.Fatal("no-UnionID login differs from native OpenID lookup and persistence")
	}
	withUnion := verifiedSubject(t, a, miniToken(t, a, "new-test-code").AccessToken)
	withoutUnion := verifiedSubject(t, a, miniToken(t, a, "no-union").AccessToken)
	if withUnion != first || withoutUnion != first || probeAccountCount(t, owner) != 1 {
		t.Fatal("UnionID presence changed subsequent native OpenID login")
	}
}

func TestWechatUnionIDAcrossProcesses(t *testing.T) {
	initializeProbe(t, true)
	owner := fmt.Sprintf("wx-process-%d", time.Now().UnixNano())
	app := createProbeApplication(t, owner, "mini", "process-mini")
	db := probeDatabase(t)
	if _, err := db.Exec("CREATE TRIGGER wechat_process_delay BEFORE INSERT ON `user` FOR EACH ROW DO SLEEP(0.2)"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec("DROP TRIGGER IF EXISTS wechat_process_delay") })
	dir := t.TempDir()
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestWechatProcessHelper$")
			cmd.Env = append(os.Environ(), "WECHAT_TEST_APP="+app.GetId(),
				"WECHAT_TEST_START="+time.Now().Add(time.Second).Format(time.RFC3339Nano),
				"WECHAT_TEST_RESULT="+filepath.Join(dir, fmt.Sprint(index)))
			output, err := cmd.CombinedOutput()
			if err != nil {
				results <- fmt.Errorf("child login failed: %w: %s", err, output)
			}
		}(i)
	}
	wg.Wait()
	close(results)
	for err := range results {
		t.Fatal(err)
	}
	first, err := os.ReadFile(filepath.Join(dir, "0"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(filepath.Join(dir, "1"))
	if err != nil {
		t.Fatal(err)
	}
	if string(first) == "" || string(first) != string(second) || probeAccountCount(t, owner) != 1 {
		t.Fatal("same UnionID created different users across processes")
	}
}

func TestWechatProcessHelper(t *testing.T) {
	appID := os.Getenv("WECHAT_TEST_APP")
	if appID == "" {
		t.Skip("child-process helper; executed by TestWechatUnionIDAcrossProcesses")
	}
	initializeProbe(t, false)
	app, err := object.GetApplication(appID)
	if err != nil || app == nil {
		t.Fatalf("read child application: %v", err)
	}
	start, err := time.Parse(time.RFC3339Nano, os.Getenv("WECHAT_TEST_START"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(start))
	subject := verifiedSubject(t, app, miniToken(t, app, "new-test-code").AccessToken)
	if err := os.WriteFile(os.Getenv("WECHAT_TEST_RESULT"), []byte(subject), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestWechatUnionIDCannotBeChangedBySelf(t *testing.T) {
	initializeProbe(t, true)
	authz.InitApi()
	web.Router("/api/update-user", &controllers.ApiController{}, "POST:UpdateUser")
	web.InsertFilter("/api/update-user", web.BeforeStatic, routers.RequestBodyFilter)
	web.InsertFilter("/api/update-user", web.BeforeRouter, routers.AutoSigninFilter)
	web.InsertFilter("/api/update-user", web.BeforeRouter, routers.ApiFilter)
	owner := fmt.Sprintf("wx-trusted-%d", time.Now().UnixNano())
	app := createProbeApplication(t, owner, "mini", "trusted-mini")
	token := miniToken(t, app, "new-test-code")
	user, err := object.GetUserByUserId(owner, verifiedSubject(t, app, token.AccessToken))
	if err != nil || user == nil {
		t.Fatalf("read authenticated user: %v", err)
	}
	body, err := json.Marshal(map[string]any{
		"properties": map[string]string{object.UserPropertiesWechatUnionId: "forged-union"},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(web.BeeApp.Handlers)
	defer server.Close()
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/update-user?id="+user.GetId()+"&columns=properties", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var envelope struct{ Status, Msg string }
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Status != "ok" {
		t.Fatalf("native authenticated update failed: %s", envelope.Msg)
	}
	current, err := object.GetUser(user.GetId())
	if err != nil || current == nil || current.Properties[object.UserPropertiesWechatUnionId] != "same-real-union" {
		t.Fatal("self update changed the trusted UnionID")
	}
}
