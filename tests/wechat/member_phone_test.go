package wechat_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

type phoneTransport struct {
	base  http.RoundTripper
	calls *atomic.Int32
	used  *sync.Map
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
	return &http.Response{StatusCode: 200, Header: make(http.Header),
		Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
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
	app.Scopes = []*object.ScopeItem{{Name: "phone:write"}}
	if _, err := object.UpdateApplication(app.GetId(), app, true, "en", nil); err != nil {
		t.Fatal("phone scopes update failed")
	}
	var err error
	app, err = object.GetApplication(app.GetId())
	if err != nil || app == nil {
		t.Fatal("phone application persistence read failed")
	}
	session := miniToken(t, app, "new-test-code")
	subject := verifiedSubject(t, app, session.AccessToken)
	db := probeDatabase(t)
	syncer := &object.Syncer{Owner: "admin", Name: app.Name, Organization: app.Organization,
		Type: "Database", TableColumns: []*object.TableColumn{
			{Name: "phone", CasdoorName: "Phone", IsHashed: true},
			{Name: "country", CasdoorName: "CountryCode", IsHashed: true},
		}}
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
	restorePool := limitBusinessPool(t, 1)
	server := httptest.NewServer(web.BeeApp.Handlers)
	defer server.Close()
	values := url.Values{"access_token": {session.AccessToken}, "app_id": {"phone-mini"},
		"code": {"trusted-phone-code"}}
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
	values.Set("access_token", session.IdToken)
	if status := memberMutation(t, server.URL, "member-phone", app, values); status != http.StatusUnauthorized {
		t.Fatal("ID token authorized phone mutation")
	}
	values.Set("access_token", session.AccessToken)
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
	restorePool()
}
