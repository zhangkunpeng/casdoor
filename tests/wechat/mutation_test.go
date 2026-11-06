package wechat_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/authz"
	"github.com/casdoor/casdoor/controllers"
	"github.com/casdoor/casdoor/idp"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/routers"
	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/xorm/contexts"
	"golang.org/x/oauth2"
)

var phoneFiltersOnce sync.Once

var probeHooks queryHooks

type queryHooks struct {
	mu    sync.RWMutex
	hooks []contexts.Hook
}

func (h *queryHooks) snapshot() []contexts.Hook {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return append([]contexts.Hook(nil), h.hooks...)
}

func (h *queryHooks) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	for _, hook := range h.snapshot() {
		if _, err := hook.BeforeProcess(c); err != nil {
			return c.Ctx, err
		}
	}
	return c.Ctx, nil
}

func (h *queryHooks) AfterProcess(c *contexts.ContextHook) error {
	for _, hook := range h.snapshot() {
		if err := hook.AfterProcess(c); err != nil {
			return err
		}
	}
	return nil
}

func registerProbeHook(t *testing.T, hook contexts.Hook) {
	t.Helper()
	probeHooks.mu.Lock()
	probeHooks.hooks = append(probeHooks.hooks, hook)
	probeHooks.mu.Unlock()
	t.Cleanup(func() {
		probeHooks.mu.Lock()
		defer probeHooks.mu.Unlock()
		for i, current := range probeHooks.hooks {
			if current == hook {
				probeHooks.hooks = append(probeHooks.hooks[:i], probeHooks.hooks[i+1:]...)
				return
			}
		}
	})
}

func phoneServer(t *testing.T) *httptest.Server {
	t.Helper()
	phoneFiltersOnce.Do(func() {
		authz.InitApi()
		web.Router("/api/login/oauth/member-phone", &controllers.ApiController{}, "POST:MemberPhone")
		web.InsertFilter("/api/login/oauth/member-phone", web.BeforeStatic, routers.RequestBodyFilter)
		web.InsertFilter("/api/login/oauth/member-phone", web.BeforeRouter, routers.AutoSigninFilter)
		web.InsertFilter("/api/login/oauth/member-phone", web.BeforeRouter, routers.ApiFilter)
	})
	server := httptest.NewServer(web.BeeApp.Handlers)
	t.Cleanup(server.Close)
	return server
}

func TestWechatPhoneRejectsApplicationTokens(t *testing.T) {
	initializeProbe(t, true)
	server := phoneServer(t)
	calls := &atomic.Int32{}
	base := http.DefaultTransport
	http.DefaultTransport = phoneTransport{base, calls, &sync.Map{}}
	t.Cleanup(func() { http.DefaultTransport = base })
	for _, format := range []string{"JWT", "JWT-Empty", "JWT-Standard", "JWT-Custom"} {
		t.Run(format, func(t *testing.T) {
			app := createProbeApplication(t, fmt.Sprintf("wx-subject-%d", time.Now().UnixNano()), "mini", "subject-mini")
			app.TokenFormat = format
			app.GrantTypes = append(app.GrantTypes, "client_credentials")
			if _, err := object.UpdateApplication(app.GetId(), app, true, "en", []string{"token_format", "grant_types"}); err != nil {
				t.Fatal(err)
			}
			var err error
			app, err = object.GetApplication(app.GetId())
			if err != nil {
				t.Fatal(err)
			}
			user := &object.User{Owner: app.Organization, Name: app.Name, SignupApplication: app.Name}
			if _, err := object.AddUser(user, "en"); err != nil {
				t.Fatal(err)
			}
			token, tokenError, err := object.GetClientCredentialsToken(app, app.ClientSecret, "", "127.0.0.1:8000")
			if err != nil || tokenError != nil || token == nil {
				t.Fatalf("mint application token: %v / %v", err, tokenError)
			}
			if err := object.BindMemberPhone(app, token.AccessToken, "subject-mini", "direct-"+format); !errors.Is(err, object.ErrMemberUnauthenticated) {
				t.Fatalf("direct application binding: %v", err)
			}
			status := memberMutation(t, server.URL, "member-phone", app, url.Values{
				"token": {token.AccessToken}, "app_id": {"subject-mini"}, "code": {format},
			})
			current, err := object.GetUser(user.GetId())
			if err != nil || current == nil {
				t.Fatal(err)
			}
			if status != http.StatusUnauthorized || current.Phone != "" || calls.Load() != 0 {
				t.Fatalf("application authorized a user: HTTP=%d calls=%d", status, calls.Load())
			}
			userToken := miniToken(t, app, "new-test-code")
			status = memberMutation(t, server.URL, "member-phone", app, url.Values{
				"token": {userToken.AccessToken}, "app_id": {"subject-mini"}, "code": {"user-" + format},
			})
			if status != http.StatusOK {
				t.Fatalf("native user format rejected: HTTP=%d", status)
			}
			calls.Store(0)
		})
	}
}

func TestWechatPhoneFiltersPreserveErrors(t *testing.T) {
	initializeProbe(t, true)
	app := createProbeApplication(t, fmt.Sprintf("wx-filter-%d", time.Now().UnixNano()), "mini", "filter-mini")
	server := phoneServer(t)
	calls := &atomic.Int32{}
	base := http.DefaultTransport
	http.DefaultTransport = phoneTransport{base, calls, &sync.Map{}}
	t.Cleanup(func() { http.DefaultTransport = base })
	if status := memberMutation(t, server.URL, "member-phone", app, url.Values{
		"token": {"not-a-token"}, "app_id": {"filter-mini"}, "code": {"unused"},
	}); status != http.StatusUnauthorized || calls.Load() != 0 {
		t.Fatalf("inactive contract: HTTP=%d calls=%d", status, calls.Load())
	}
	token := miniToken(t, app, "new-test-code")
	app.ClientSecret = "wrong"
	if status := memberMutation(t, server.URL, "member-phone", app, url.Values{
		"token": {token.AccessToken}, "app_id": {"filter-mini"}, "code": {"unused"},
	}); status != http.StatusUnauthorized || calls.Load() != 0 {
		t.Fatalf("application authentication: HTTP=%d calls=%d", status, calls.Load())
	}
	app, err := object.GetApplication(app.GetId())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := object.ExpireToken(token); err != nil {
		t.Fatal(err)
	}
	if status := memberMutation(t, server.URL, "member-phone", app, url.Values{
		"token": {token.AccessToken}, "app_id": {"filter-mini"}, "code": {"unused"},
	}); status != http.StatusUnauthorized || calls.Load() != 0 {
		t.Fatalf("expired user authentication: HTTP=%d calls=%d", status, calls.Load())
	}
	active := miniToken(t, app, "new-test-code")
	user, err := object.GetUser(util.GetId(active.Organization, active.User))
	if err != nil {
		t.Fatal(err)
	}
	user.IsForbidden = true
	if _, err := object.UpdateUser(user.GetId(), user, []string{"is_forbidden"}, true); err != nil {
		t.Fatal(err)
	}
	if status := memberMutation(t, server.URL, "member-phone", app, url.Values{
		"token": {active.AccessToken}, "app_id": {"filter-mini"}, "code": {"unused"},
	}); status != http.StatusUnauthorized || calls.Load() != 0 {
		t.Fatalf("forbidden user authentication: HTTP=%d calls=%d", status, calls.Load())
	}
}

type tokenReadFailure struct{ active atomic.Bool }

func (f *tokenReadFailure) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if f.active.Load() && strings.HasPrefix(c.SQL, "SELECT") && strings.Contains(c.SQL, "access_token_hash") {
		return c.Ctx, errors.New("injected token read failure")
	}
	return c.Ctx, nil
}

func (f *tokenReadFailure) AfterProcess(_ *contexts.ContextHook) error { return nil }

func TestWechatPhoneFiltersPreserveDependencyFailure(t *testing.T) {
	initializeProbe(t, true)
	app := createProbeApplication(t, fmt.Sprintf("wx-dependency-%d", time.Now().UnixNano()), "mini", "dependency-mini")
	token := miniToken(t, app, "new-test-code")
	server := phoneServer(t)
	base := http.DefaultTransport
	calls := &atomic.Int32{}
	http.DefaultTransport = phoneTransport{base, calls, &sync.Map{}}
	t.Cleanup(func() { http.DefaultTransport = base })
	failure := &tokenReadFailure{}
	registerProbeHook(t, failure)
	failure.active.Store(true)
	defer failure.active.Store(false)
	if status := memberMutation(t, server.URL, "member-phone", app, url.Values{
		"token": {token.AccessToken}, "app_id": {"dependency-mini"}, "code": {"unused"},
	}); status != http.StatusServiceUnavailable || calls.Load() != 0 {
		t.Fatalf("token dependency failure: HTTP=%d calls=%d", status, calls.Load())
	}
}

func TestWechatOAuthMutationKeepsCurrentUnion(t *testing.T) {
	initializeProbe(t, true)
	app := createProbeApplication(t, fmt.Sprintf("wx-current-%d", time.Now().UnixNano()), "mini", "current-mini")
	user := &object.User{Owner: app.Organization, Name: "official-user", SignupApplication: app.Name, WeChat: "official-open"}
	if _, err := object.AddUser(user, "en"); err != nil {
		t.Fatal(err)
	}
	org, err := object.GetOrganization("admin/" + app.Organization)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := object.GetUser(user.GetId())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := object.SetUserOAuthProperties(org, user, "WeChat", &idp.UserInfo{Id: "official-open", UnionId: "same-real-union"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := object.SetUserOAuthProperties(org, stale, "WeChat", &idp.UserInfo{Id: "official-open"}, nil); err != nil {
		t.Fatal(err)
	}
	if stale.Properties[object.UserPropertiesWechatUnionId] != "same-real-union" {
		t.Fatal("committed caller snapshot lost current UnionID")
	}
	token := miniToken(t, app, "new-test-code")
	if verifiedSubject(t, app, token.AccessToken) != user.Id || probeAccountCount(t, app.Organization) != 1 {
		t.Fatal("stale OAuth mutation split the native account")
	}
}

type userReadBarrier struct {
	owner   string
	phone   string
	sql     string
	armed   atomic.Bool
	reached chan struct{}
	resume  chan struct{}
}

func (b *userReadBarrier) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	return c.Ctx, nil
}

func (b *userReadBarrier) AfterProcess(c *contexts.ContextHook) error {
	if !strings.HasPrefix(c.SQL, "SELECT") || !strings.Contains(c.SQL, "`user`") ||
		strings.Contains(c.SQL, "FOR UPDATE") {
		return nil
	}
	matched := strings.Contains(c.SQL, "wechat = ? OR wechat = ?")
	if b.sql != "" {
		matched = strings.Contains(c.SQL, b.sql)
	}
	if b.phone != "" {
		matched = false
		for _, arg := range c.Args {
			matched = matched || arg == b.phone
		}
	}
	if !matched {
		return nil
	}
	for _, arg := range c.Args {
		if arg == b.owner && b.armed.CompareAndSwap(true, false) {
			close(b.reached)
			<-b.resume
			break
		}
	}
	return nil
}

func TestWechatMiniPhoneSelectionRechecksCurrentAccount(t *testing.T) {
	initializeProbe(t, true)
	for _, scenario := range []string{"phone-changed", "wechat-linked", "unchanged"} {
		t.Run(scenario, func(t *testing.T) {
			app := createProbeApplication(t, fmt.Sprintf("wx-select-%d", time.Now().UnixNano()), "mini", "select-mini")
			user := &object.User{
				Owner: app.Organization, Name: "phone-user", SignupApplication: app.Name,
				Phone: "13800000000", CountryCode: "CN",
			}
			if _, err := object.AddUser(user, "en"); err != nil {
				t.Fatal(err)
			}
			base := http.DefaultTransport
			http.DefaultTransport = phoneTransport{base, &atomic.Int32{}, &sync.Map{}}
			t.Cleanup(func() { http.DefaultTransport = base })
			barrier := &userReadBarrier{owner: user.Owner, phone: user.Phone, reached: make(chan struct{}), resume: make(chan struct{})}
			barrier.armed.Store(true)
			registerProbeHook(t, barrier)
			var once sync.Once
			resume := func() { barrier.armed.Store(false); once.Do(func() { close(barrier.resume) }) }
			defer resume()
			done := make(chan error, 1)
			go func() {
				_, tokenError, err := object.GetWechatMiniProgramToken(app, "no-union", scenario, false, "127.0.0.1:8000", "", "", "en")
				if tokenError != nil {
					err = fmt.Errorf("mini selection: %v", tokenError)
				}
				done <- err
			}()
			select {
			case <-barrier.reached:
			case <-time.After(10 * time.Second):
				t.Fatal("phone selection did not reach barrier")
			}
			if scenario == "phone-changed" {
				user.Phone = "13800111111"
			} else if scenario == "wechat-linked" {
				user.WeChat = "another-openid"
			}
			if _, err := object.UpdateUser(user.GetId(), user, []string{"phone", "wechat"}, true); err != nil {
				resume()
				<-done
				t.Fatal(err)
			}
			resume()
			err := <-done
			if (err == nil) != (scenario == "unchanged") {
				t.Fatalf("selected account outcome: %v", err)
			}
			current, err := object.GetUser(user.GetId())
			if err != nil {
				t.Fatal(err)
			}
			expectedWeChat := user.WeChat
			if scenario == "unchanged" {
				expectedWeChat = "mini-open"
			}
			if current.Phone != user.Phone || current.WeChat != expectedWeChat || current.Id != user.Id {
				t.Fatal("stale phone selection changed the account")
			}
		})
	}
}

func TestWechatOAuthMappingAndProviderLink(t *testing.T) {
	initializeProbe(t, true)
	app := createProbeApplication(t, fmt.Sprintf("wx-map-%d", time.Now().UnixNano()), "mini", "map-mini")
	token := miniToken(t, app, "new-test-code")
	user, err := object.GetUser(util.GetId(token.Organization, token.User))
	if err != nil {
		t.Fatal(err)
	}
	group := &object.Group{Owner: user.Owner, Name: "members"}
	if _, err := object.AddGroup(group); err != nil {
		t.Fatal(err)
	}
	user.Groups = []string{group.GetId()}
	user.Properties["oauth_WeChat_extra"] = `{"retained":"old"}`
	if _, err := object.UpdateUser(user.GetId(), user, []string{"groups", "properties"}, true); err != nil {
		t.Fatal(err)
	}
	stale, err := object.GetUser(user.GetId())
	if err != nil {
		t.Fatal(err)
	}
	base := http.DefaultTransport
	http.DefaultTransport = phoneTransport{base, &atomic.Int32{}, &sync.Map{}}
	t.Cleanup(func() { http.DefaultTransport = base })
	if err := object.BindMemberPhone(app, token.AccessToken, "map-mini", "map-phone"); err != nil {
		t.Fatal(err)
	}
	org, err := object.GetOrganization("admin/" + user.Owner)
	if err != nil {
		t.Fatal(err)
	}
	info := &idp.UserInfo{
		Id: "official-open", DisplayName: "OAuth Name", Email: "member@example.com",
		AvatarUrl: "https://example.com/avatar.png", Extra: map[string]string{
			"title": "Member", "phone": "unverified", "name": "replacement", "groups": "other",
		},
	}
	mapping := map[string]string{"title": "title", "phone": "phone", "name": "name", "groups": "groups"}
	if _, err := object.SetUserOAuthProperties(org, stale, "WeChat", info,
		&oauth2.Token{AccessToken: "provider-access", RefreshToken: "provider-refresh"}, mapping); err != nil {
		t.Fatal(err)
	}
	if stale.Phone != "13800000000" || stale.Title != "Member" || stale.Name != user.Name ||
		stale.DisplayName != "OAuth Name" || stale.Email != info.Email || stale.Avatar != info.AvatarUrl ||
		stale.OriginalToken != "provider-access" || !reflect.DeepEqual(stale.Groups, user.Groups) ||
		!strings.Contains(stale.Properties["oauth_WeChat_extra"], `"retained":"old"`) {
		t.Fatal("OAuth mapping lost current data or native mapped fields")
	}
	if err := object.BindMemberPhone(app, token.AccessToken, "map-mini", "fresh-phone-code"); err != nil {
		t.Fatal(err)
	}
	if linked, err := object.LinkUserAccount(stale, "WeChat", "official-open"); err != nil || !linked {
		t.Fatalf("provider link: %t / %v", linked, err)
	}
	if stale.Phone != "13800111111" || stale.WeChat != "official-open" {
		t.Fatal("provider link used an old caller snapshot")
	}
	for _, provider := range []struct{ name, field string }{
		{"GitLab", "Gitlab"},
		{"ADFS", "Adfs"},
		{"AzureADB2C", "AzureADB2c"},
		{"WeCom", "Wecom"},
		{"PayPal", "Paypal"},
		{"OIDC", "Oidc"},
	} {
		if _, err := object.LinkUserAccount(stale, provider.name, "provider-id"); err != nil {
			t.Fatalf("native provider %s: %v", provider.name, err)
		}
		if object.GetUserField(stale, provider.field) != "provider-id" {
			t.Fatalf("provider %s binding missing", provider.name)
		}
	}
	members, err := object.GetGroupUsers(group.GetId())
	if err != nil || len(members) != 1 || members[0].Id != user.Id {
		t.Fatalf("OAuth mapping changed group membership: %v", err)
	}
	before := *stale
	before.Properties = make(map[string]string, len(stale.Properties))
	for key, value := range stale.Properties {
		before.Properties[key] = value
	}
	db := probeDatabase(t)
	if _, err := db.Exec("CREATE TRIGGER wechat_mapping_failure BEFORE UPDATE ON `user` FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'injected mapping failure'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec("DROP TRIGGER IF EXISTS wechat_mapping_failure") })
	if _, err := object.SetUserOAuthProperties(org, stale, "WeChat", &idp.UserInfo{Id: "failed-id"}, nil); err == nil {
		t.Fatal("mapping persistence failure reported success")
	}
	if !reflect.DeepEqual(before, *stale) {
		t.Fatal("failed mapping mutated the caller")
	}
	current, err := object.GetUser(stale.GetId())
	if err != nil || !reflect.DeepEqual(current.Properties, before.Properties) || current.Phone != before.Phone {
		t.Fatalf("failed mapping changed persisted data: %v", err)
	}
}

func TestWechatMiniMutationHashesCurrentPhone(t *testing.T) {
	initializeProbe(t, true)
	app := createProbeApplication(t, fmt.Sprintf("wx-hash-current-%d", time.Now().UnixNano()), "mini", "hash-current-mini")
	token := miniToken(t, app, "no-union")
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
	if _, err := probeDatabase(t).Exec("UPDATE syncer SET is_enabled = true WHERE owner = ? AND name = ?", syncer.Owner, syncer.Name); err != nil {
		t.Fatal(err)
	}
	base := http.DefaultTransport
	http.DefaultTransport = phoneTransport{base, &atomic.Int32{}, &sync.Map{}}
	t.Cleanup(func() { http.DefaultTransport = base })
	barrier := &userReadBarrier{owner: app.Organization, reached: make(chan struct{}), resume: make(chan struct{})}
	barrier.armed.Store(true)
	registerProbeHook(t, barrier)
	var release sync.Once
	resume := func() { barrier.armed.Store(false); release.Do(func() { close(barrier.resume) }) }
	defer resume()
	done := make(chan error, 1)
	go func() {
		_, tokenError, err := object.GetWechatMiniProgramToken(app, "new-test-code", "", false, "127.0.0.1:8000", "", "", "en")
		if tokenError != nil {
			err = fmt.Errorf("mini token: %v", tokenError)
		}
		done <- err
	}()
	select {
	case <-barrier.reached:
	case <-time.After(10 * time.Second):
		t.Fatal("native mini lookup did not reach barrier")
	}
	err := object.BindMemberPhone(app, token.AccessToken, "hash-current-mini", "fresh-current")
	resume()
	if loginErr := <-done; loginErr != nil {
		t.Fatal(loginErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	current, err := object.GetUser(util.GetId(token.Organization, token.User))
	if err != nil || current == nil {
		t.Fatal(err)
	}
	expected := *current
	if err := expected.UpdateUserHash(); err != nil {
		t.Fatal(err)
	}
	if current.Phone != "13800000000" || current.Hash != expected.Hash ||
		current.Properties[object.UserPropertiesWechatUnionId] != "same-real-union" {
		t.Fatal("mini promotion did not persist current phone, UnionID and matching Hash")
	}
}
