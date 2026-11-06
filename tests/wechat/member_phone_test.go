package wechat_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/controllers"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

func TestWechatMemberPhoneFreshCodeForAlreadyBoundPhone(t *testing.T) {
	initializeProbe(t, true)
	app := createProbeApplication(t, fmt.Sprintf("wx-phone-repeat-%d", time.Now().UnixNano()), "mini", "repeat-mini")
	token := miniToken(t, app, "new-test-code")
	base := http.DefaultTransport
	http.DefaultTransport = phoneTransport{base, &atomic.Int32{}, &sync.Map{}}
	t.Cleanup(func() { http.DefaultTransport = base })
	web.Router("/api/login/oauth/member-phone", &controllers.ApiController{}, "POST:MemberPhone")
	server := httptest.NewServer(web.BeeApp.Handlers)
	defer server.Close()
	user, err := object.GetUser(util.GetId(token.Organization, token.User))
	if err != nil || user == nil {
		t.Fatalf("read phone user: %v", err)
	}
	user.Phone, user.CountryCode = "13800000000", "CN"
	for attempt := 0; attempt < 5; attempt++ {
		if _, err := object.UpdateUser(user.GetId(), user, []string{"phone", "country_code"}, true); err != nil {
			t.Fatal(err)
		}
		second := util.GetCurrentTime()
		if user.UpdatedTime != second {
			continue
		}
		status := memberMutation(t, server.URL, "member-phone", app, url.Values{
			"token": {token.AccessToken}, "app_id": {"repeat-mini"}, "code": {fmt.Sprintf("fresh-noop-%d", attempt)},
		})
		if second != util.GetCurrentTime() {
			continue
		}
		if status != http.StatusOK {
			t.Fatalf("fresh code for unchanged locked phone returned %d", status)
		}
		return
	}
	t.Fatal("could not exercise binding within one timestamp second")
}

func TestWechatMemberPhoneSingleConnection(t *testing.T) {
	initializeProbe(t, true)
	app := createProbeApplication(t, fmt.Sprintf("wx-phone-pool-%d", time.Now().UnixNano()), "mini", "pool-mini")
	t.Cleanup(func() {
		_, err := probeDatabase(t).Exec("UPDATE setting SET db_max_open_conns = 0, db_max_idle_conns = 0 WHERE owner = 'admin' AND name = 'setting-built-in'")
		if err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWechatMemberPhoneSingleConnectionHelper$")
	cmd.Env = append(os.Environ(), "WECHAT_PHONE_POOL_APP="+app.GetId())
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("single-connection phone binding did not complete: %v\n%s", err, output)
	}
}

func TestWechatMemberPhoneSingleConnectionHelper(t *testing.T) {
	appID := os.Getenv("WECHAT_PHONE_POOL_APP")
	if appID == "" {
		t.Skip("child-process helper; executed by TestWechatMemberPhoneSingleConnection")
	}
	initializeProbe(t, false)
	app, err := object.GetApplication(appID)
	if err != nil || app == nil {
		t.Fatalf("read child application: %v", err)
	}
	token := miniToken(t, app, "new-test-code")
	object.InitSetting()
	setting, err := object.GetSetting()
	if err != nil || setting == nil {
		t.Fatalf("read native pool settings: %v", err)
	}
	setting.DbMaxOpenConns, setting.DbMaxIdleConns = 1, 1
	if _, err := object.UpdateSetting(setting); err != nil {
		t.Fatal(err)
	}
	base := http.DefaultTransport
	http.DefaultTransport = phoneTransport{base, &atomic.Int32{}, &sync.Map{}}
	defer func() { http.DefaultTransport = base }()
	if err := object.BindMemberPhone(app, token.AccessToken, "pool-mini", "fresh-pool-code"); err != nil {
		t.Fatal(err)
	}
}

type phoneTransport struct {
	base  http.RoundTripper
	calls *atomic.Int32
	used  *sync.Map
}

type pausedPhoneTransport struct {
	base            http.RoundTripper
	entered, resume chan struct{}
}

func (r pausedPhoneTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != "api.weixin.qq.com" || req.URL.Path != "/wxa/business/getuserphonenumber" {
		return r.base.RoundTrip(req)
	}
	close(r.entered)
	select {
	case <-r.resume:
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
	return &http.Response{
		StatusCode: 200, Header: make(http.Header), Request: req,
		Body: io.NopCloser(strings.NewReader(`{"errcode":0,"phone_info":{"purePhoneNumber":"13800000000","countryCode":"86"}}`)),
	}, nil
}

func TestWechatMemberPhoneRechecksAuthorizationAtWrite(t *testing.T) {
	initializeProbe(t, true)
	for _, scenario := range []string{"rename-and-reuse", "forbidden", "deleted", "revoked", "expired", "expires-while-waiting-for-user", "expires-while-waiting-for-metadata"} {
		t.Run(scenario, func(t *testing.T) {
			app := createProbeApplication(t, fmt.Sprintf("wx-phone-race-%d", time.Now().UnixNano()), "mini", "race-mini")
			token := miniToken(t, app, "new-test-code")
			user, err := object.GetUser(util.GetId(token.Organization, token.User))
			if err != nil || user == nil {
				t.Fatalf("read authenticated user: %v", err)
			}
			originalName := user.Name
			entered, resume := make(chan struct{}), make(chan struct{})
			var release sync.Once
			t.Cleanup(func() { release.Do(func() { close(resume) }) })
			base := http.DefaultTransport
			http.DefaultTransport = pausedPhoneTransport{base, entered, resume}
			t.Cleanup(func() { http.DefaultTransport = base })
			done := make(chan error, 1)
			go func() { done <- object.BindMemberPhone(app, token.AccessToken, "race-mini", "race-code") }()
			select {
			case <-entered:
			case <-time.After(15 * time.Second):
				t.Fatal("phone exchange did not start")
			}
			switch scenario {
			case "rename-and-reuse":
				user.Name += "-renamed"
				if _, err := object.UpdateUser(util.GetId(user.Owner, originalName), user, []string{"name"}, true); err != nil {
					t.Fatal(err)
				}
				replacement := &object.User{
					Owner: user.Owner, Name: originalName, Id: util.GenerateId(),
					Type: "normal-user", CreatedTime: util.GetCurrentTime(),
				}
				if _, err := object.AddUser(replacement, "en"); err != nil {
					t.Fatal(err)
				}
			case "forbidden", "deleted":
				user.IsForbidden = scenario == "forbidden"
				user.IsDeleted = scenario == "deleted"
				if _, err := object.UpdateUser(user.GetId(), user, []string{"is_forbidden", "is_deleted"}, true); err != nil {
					t.Fatal(err)
				}
			case "revoked":
				if _, err := object.ExpireToken(token); err != nil {
					t.Fatal(err)
				}
			case "expired":
				if _, err := probeDatabase(t).Exec("UPDATE token SET created_time = ? WHERE owner = ? AND name = ?",
					time.Now().Add(-24*time.Hour).Format(time.RFC3339), token.Owner, token.Name); err != nil {
					t.Fatal(err)
				}
			case "expires-while-waiting-for-user":
				db := probeDatabase(t)
				if _, err := db.Exec("UPDATE token SET created_time = ?, expires_in = 1 WHERE owner = ? AND name = ?",
					util.GetCurrentTime(), token.Owner, token.Name); err != nil {
					t.Fatal(err)
				}
				tx, err := db.Begin()
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				var subject string
				if err := tx.QueryRow("SELECT id FROM `user` WHERE owner = ? AND name = ? FOR UPDATE", user.Owner, user.Name).Scan(&subject); err != nil {
					t.Fatal(err)
				}
				release.Do(func() { close(resume) })
				<-time.After(2 * time.Second)
				if err := tx.Commit(); err != nil {
					t.Fatal(err)
				}
			case "expires-while-waiting-for-metadata":
				db := probeDatabase(t)
				if _, err := db.Exec("UPDATE token SET created_time = ?, expires_in = 1 WHERE owner = ? AND name = ?",
					util.GetCurrentTime(), token.Owner, token.Name); err != nil {
					t.Fatal(err)
				}
				conn, err := db.Conn(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if _, err := conn.ExecContext(context.Background(), "LOCK TABLES syncer WRITE"); err != nil {
					t.Fatal(err)
				}
				defer conn.ExecContext(context.Background(), "UNLOCK TABLES")
				release.Do(func() { close(resume) })
				<-time.After(2 * time.Second)
				if _, err := conn.ExecContext(context.Background(), "UNLOCK TABLES"); err != nil {
					t.Fatal(err)
				}
			}
			release.Do(func() { close(resume) })
			select {
			case err := <-done:
				if !errors.Is(err, object.ErrMemberUnauthenticated) {
					t.Errorf("changed authorization accepted at write: %v", err)
				}
			case <-time.After(15 * time.Second):
				t.Fatal("phone binding did not finish")
			}
			var bound int
			if err := probeDatabase(t).QueryRow("SELECT COUNT(*) FROM `user` WHERE owner = ? AND phone <> ''", user.Owner).Scan(&bound); err != nil {
				t.Fatal(err)
			}
			if bound != 0 {
				t.Fatal("inactive authorization wrote a phone to a user")
			}
		})
	}
}

func TestWechatMemberPhoneUniqueness(t *testing.T) {
	initializeProbe(t, true)
	base := http.DefaultTransport
	http.DefaultTransport = phoneTransport{base, &atomic.Int32{}, &sync.Map{}}
	t.Cleanup(func() { http.DefaultTransport = base })
	web.Router("/api/login/oauth/member-phone", &controllers.ApiController{}, "POST:MemberPhone")
	server := httptest.NewServer(web.BeeApp.Handlers)
	defer server.Close()
	for _, concurrent := range []bool{false, true} {
		t.Run(fmt.Sprintf("concurrent=%t", concurrent), func(t *testing.T) {
			app := createProbeApplication(t, fmt.Sprintf("wx-phone-unique-%d", time.Now().UnixNano()), "mini", "unique-mini")
			first, second := miniToken(t, app, "new-test-code"), miniToken(t, app, "different-wechat")
			if concurrent {
				db := probeDatabase(t)
				if _, err := db.Exec("CREATE TRIGGER wechat_phone_delay BEFORE UPDATE ON `user` FOR EACH ROW DO SLEEP(0.2)"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { db.Exec("DROP TRIGGER IF EXISTS wechat_phone_delay") })
			}
			bind := func(token *object.Token, code string) int {
				return memberMutation(t, server.URL, "member-phone", app, url.Values{
					"token": {token.AccessToken}, "app_id": {"unique-mini"}, "code": {code},
				})
			}
			results := make(chan int, 2)
			if concurrent {
				go func() { results <- bind(first, "unique-concurrent-a") }()
				go func() { results <- bind(second, "unique-concurrent-b") }()
			} else {
				results <- bind(first, "unique-sequential-a")
				results <- bind(second, "unique-sequential-b")
			}
			a, b := <-results, <-results
			if !((a == http.StatusOK && b == http.StatusBadRequest) || (b == http.StatusOK && a == http.StatusBadRequest)) {
				t.Fatalf("same trusted phone assigned to two subjects: statuses=%d,%d", a, b)
			}
			var bound int
			if err := probeDatabase(t).QueryRow("SELECT COUNT(*) FROM `user` WHERE owner = ? AND phone = '13800000000' AND country_code = 'CN'",
				app.Organization).Scan(&bound); err != nil {
				t.Fatal(err)
			}
			if bound != 1 {
				t.Fatalf("phone owners=%d, want 1", bound)
			}
			for _, token := range []*object.Token{first, second} {
				user, err := object.GetUser(util.GetId(token.Organization, token.User))
				if err != nil || user == nil {
					t.Fatalf("read phone account: %v", err)
				}
				normalized := *user
				normalized.Phone, normalized.CountryCode = "+8613800000000", "CN"
				msg := object.CheckUpdateUser(user, &normalized, "en")
				if (msg == "") != (user.Phone != "") || normalized.Phone != "13800000000" || normalized.CountryCode != "CN" {
					t.Fatal("phone binding and native normalized uniqueness rule disagree")
				}
			}
		})
	}
}

func (r phoneTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != "api.weixin.qq.com" || req.URL.Path != "/wxa/business/getuserphonenumber" {
		return r.base.RoundTrip(req)
	}
	r.calls.Add(1)
	var request struct{ Code string }
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		return nil, fmt.Errorf("invalid phone authorization request")
	}
	body := `{"errcode":0,"phone_info":{"purePhoneNumber":"13800000000","countryCode":"86"}}`
	if request.Code == "retryable-phone-code" || request.Code == "fresh-phone-code" {
		body = `{"errcode":0,"phone_info":{"purePhoneNumber":"13800111111","countryCode":"86"}}`
	}
	if _, loaded := r.used.LoadOrStore(request.Code, true); loaded {
		body = `{"errcode":40029}`
	}
	return &http.Response{
		StatusCode: 200, Header: make(http.Header),
		Body: io.NopCloser(strings.NewReader(body)), Request: req,
	}, nil
}

func memberMutation(t *testing.T, server, path string, app *object.Application, values url.Values) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, server+"/api/login/oauth/"+path, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatal("member mutation request creation failed")
	}
	req.SetBasicAuth(app.ClientId, app.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal("member mutation request failed")
	}
	defer response.Body.Close()
	return response.StatusCode
}

func TestWechatMemberPhone(t *testing.T) {
	initializeProbe(t, true)
	base := http.DefaultTransport
	calls, used := &atomic.Int32{}, &sync.Map{}
	http.DefaultTransport = phoneTransport{base: base, calls: calls, used: used}
	t.Cleanup(func() { http.DefaultTransport = base })
	web.Router("/api/login/oauth/member-phone", &controllers.ApiController{}, "POST:MemberPhone")
	app := createProbeApplication(t, fmt.Sprintf("wx-phone-%d", time.Now().UnixNano()), "mini", "phone-mini")
	var err error
	app, err = object.GetApplication(app.GetId())
	if err != nil || app == nil {
		t.Fatal("phone application persistence read failed")
	}
	session := miniToken(t, app, "new-test-code")
	subject := verifiedSubject(t, app, session.AccessToken)
	db := probeDatabase(t)
	syncer := &object.Syncer{
		Owner: "admin", Name: app.Name, Organization: app.Organization,
		Type: "Database", TableColumns: []*object.TableColumn{
			{Name: "phone", CasdoorName: "Phone", IsHashed: true},
			{Name: "country", CasdoorName: "CountryCode", IsHashed: true},
		},
	}
	if _, err := object.AddSyncer(syncer); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { object.DeleteSyncer(syncer) })
	// Enable only the persisted hash configuration; this test never starts an external synchronization job.
	if _, err := db.Exec("UPDATE syncer SET is_enabled = true WHERE owner = ? AND name = ?", syncer.Owner, syncer.Name); err != nil {
		t.Fatal(err)
	}
	before, err := object.GetUserByUserId(app.Organization, subject)
	if err != nil || before == nil {
		t.Fatal("phone account unavailable")
	}
	if err := before.UpdateUserHash(); err != nil {
		t.Fatal(err)
	}
	before.PreHash = before.Hash
	if _, err := object.UpdateUser(before.GetId(), before, []string{"pre_hash"}, true); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-time.Hour).Format(time.RFC3339)
	if _, err := db.Exec("UPDATE `user` SET updated_time = ? WHERE owner = ? AND name = ?", oldTime, before.Owner, before.Name); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(web.BeeApp.Handlers)
	defer server.Close()
	values := url.Values{
		"token": {session.AccessToken}, "app_id": {"phone-mini"},
		"code": {"trusted-phone-code"},
	}
	for _, denied := range []struct {
		field, value string
		status       int
	}{
		{"token", "", http.StatusUnauthorized},
		{"token", session.IdToken, http.StatusUnauthorized},
		{"token", session.RefreshToken, http.StatusUnauthorized},
		{"app_id", "unconfigured-mini", http.StatusForbidden},
		{"code", "", http.StatusBadRequest},
	} {
		old := values.Get(denied.field)
		values.Set(denied.field, denied.value)
		if status := memberMutation(t, server.URL, "member-phone", app, values); status != denied.status {
			t.Fatalf("invalid %s: status=%d, want=%d", denied.field, status, denied.status)
		}
		values.Set(denied.field, old)
	}
	other := createProbeApplication(t, fmt.Sprintf("wx-other-phone-%d", time.Now().UnixNano()), "mini", "other-mini")
	if status := memberMutation(t, server.URL, "member-phone", other, values); status != http.StatusUnauthorized {
		t.Fatal("another application accepted this access token")
	}
	if calls.Load() != 0 {
		t.Fatal("invalid phone request reached WeChat")
	}
	if status := memberMutation(t, server.URL, "member-phone", app, values); status != http.StatusOK {
		t.Fatalf("trusted phone binding failed: status=%d", status)
	}
	user, err := object.GetUserByUserId(app.Organization, subject)
	if err != nil || user == nil || user.Phone != "13800000000" || user.CountryCode != "CN" {
		t.Fatal("trusted phone not persisted on the authenticated Casdoor subject")
	}
	expected := *user
	if err := expected.UpdateUserHash(); err != nil {
		t.Fatal(err)
	}
	if user.Hash != expected.Hash || user.Hash == user.PreHash || user.UpdatedTime == oldTime ||
		util.String2Time(user.UpdatedTime).Before(util.String2Time(oldTime)) {
		t.Error("phone update did not maintain native hash and modification time")
	}
	persistedHash, persistedTime := user.Hash, user.UpdatedTime
	if status := memberMutation(t, server.URL, "member-phone", app, values); status != http.StatusServiceUnavailable {
		t.Fatal("consumed authorization code was treated as a recoverable operation")
	}
	values.Set("token", session.IdToken)
	if status := memberMutation(t, server.URL, "member-phone", app, values); status != http.StatusUnauthorized {
		t.Fatal("ID token authorized phone mutation")
	}
	values.Set("token", session.AccessToken)
	values.Set("code", "retryable-phone-code")
	if _, err := db.Exec("CREATE TRIGGER xueda_phone_failure BEFORE UPDATE ON `user` FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'injected phone write failure'"); err != nil {
		t.Fatal("phone failure trigger creation failed")
	}
	t.Cleanup(func() { db.Exec("DROP TRIGGER IF EXISTS xueda_phone_failure") })
	if status := memberMutation(t, server.URL, "member-phone", app, values); status != http.StatusServiceUnavailable {
		t.Fatal("phone persistence failure reported success")
	}
	user, err = object.GetUserByUserId(app.Organization, subject)
	if err != nil || user == nil || user.Phone != "13800000000" || user.Hash != persistedHash || user.UpdatedTime != persistedTime {
		t.Fatal("failed phone transaction changed the current profile")
	}
	if _, err := db.Exec("DROP TRIGGER xueda_phone_failure"); err != nil {
		t.Fatal("phone failure trigger cleanup failed")
	}
	if status := memberMutation(t, server.URL, "member-phone", app, values); status != http.StatusServiceUnavailable {
		t.Fatal("failed write retained the consumed phone authorization")
	}
	values.Set("code", "fresh-phone-code")
	if status := memberMutation(t, server.URL, "member-phone", app, values); status != http.StatusOK {
		t.Fatal("fresh phone authorization did not recover the failed write")
	}
	user, err = object.GetUserByUserId(app.Organization, subject)
	if err != nil || user == nil || user.Phone != "13800111111" || user.CountryCode != "CN" {
		t.Fatal("freshly authorized phone not persisted")
	}
	expected = *user
	if err := expected.UpdateUserHash(); err != nil {
		t.Fatal(err)
	}
	if user.Hash != expected.Hash || user.Hash == persistedHash || user.PreHash != before.PreHash {
		t.Error("fresh authorization did not persist the native synchronization hash")
	}
	if calls.Load() != 5 {
		t.Fatal("phone authorization requests did not follow native one-use verification")
	}
	if _, err := object.ExpireToken(session); err != nil {
		t.Fatal(err)
	}
	if status := memberMutation(t, server.URL, "member-phone", app, values); status != http.StatusUnauthorized {
		t.Fatal("revoked token mutated phone")
	}
	session = miniToken(t, app, "new-test-code")
	values.Set("token", session.AccessToken)
	user.IsForbidden = true
	if _, err := object.UpdateUser(user.GetId(), user, []string{"is_forbidden"}, true); err != nil {
		t.Fatal("member disable failed")
	}
	if status := memberMutation(t, server.URL, "member-phone", app, values); status != http.StatusUnauthorized {
		t.Fatal("disabled subject mutated phone")
	}
	users := probeAccountCount(t, app.Organization)
	if users != 1 {
		t.Fatal("phone binding created a second account")
	}
}
