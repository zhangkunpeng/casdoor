package wechat_test

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beego/beego/v2/server/web"
	"github.com/casdoor/casdoor/controllers"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/proxy"
	"github.com/golang-jwt/jwt/v5"
)

type wechatTransport struct {
	base          http.RoundTripper
	officialUnion *atomic.Bool
}

func (r wechatTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != "api.weixin.qq.com" {
		return r.base.RoundTrip(req)
	}
	var body string
	switch req.URL.Path {
	case "/sns/jscode2session":
		body = `{"openid":"mini-open","unionid":"same-real-union","session_key":"test-only"}`
		if req.URL.Query().Get("js_code") == "different-wechat" {
			body = `{"openid":"different-open","unionid":"different-union","session_key":"test-only"}`
		}
		if req.URL.Query().Get("js_code") == "case-distinct" {
			body = `{"openid":"case-distinct-open","unionid":"Same-real-union","session_key":"test-only"}`
		}
		if req.URL.Query().Get("js_code") == "no-union" {
			body = `{"openid":"mini-open","session_key":"test-only"}`
		}
	case "/cgi-bin/token", "/cgi-bin/stable_token":
		body = `{"access_token":"test-only","expires_in":7200}`
	case "/cgi-bin/user/info":
		body = `{"openid":"official-open","unionid":"same-real-union"}`
		if !r.officialUnion.Load() {
			body = `{"openid":"official-open"}`
		}
	default:
		return nil, fmt.Errorf("unexpected WeChat request %s", req.URL.Path)
	}
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
}

func TestWechatRegistrationOrdersAndConcurrency(t *testing.T) {
	if os.Getenv("CASDOOR_WECHAT_TEST_DSN") == "" {
		t.Skip("requires isolated MySQL CASDOOR_WECHAT_TEST_DSN")
	}
	initializeProbe(t, true)
	baseTransport := http.DefaultTransport
	officialUnion := &atomic.Bool{}
	officialUnion.Store(true)
	http.DefaultTransport = wechatTransport{baseTransport, officialUnion}
	t.Cleanup(func() { http.DefaultTransport = baseTransport })
	proxy.InitHttpClient()
	web.Router("/api/login", &controllers.ApiController{}, "POST:Login")
	web.Router("/api/webhook", &controllers.ApiController{}, "POST:HandleOfficialAccountEvent")
	server := httptest.NewServer(web.BeeApp.Handlers)
	defer server.Close()
	cert, err := object.GetCert("admin/cert-built-in")
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cert.Certificate))
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"mini-first", "official-first", "concurrent", "union-upgrade", "official-subscribe", "different-union-case", "official-openid-only", "mini-openid-only", "official-union-upgrade", "official-stale"} {
		t.Run(scenario, func(t *testing.T) {
			officialUnion.Store(scenario != "official-openid-only" && scenario != "official-union-upgrade" && scenario != "official-stale")
			owner := fmt.Sprintf("wx-%s-%d", scenario, time.Now().UnixNano())
			org := &object.Organization{Owner: "admin", Name: owner, PasswordType: "bcrypt", DefaultTokenFormat: "JWT"}
			if _, err := object.AddOrganization(org); err != nil {
				t.Fatal(err)
			}
			mini := &object.Provider{Owner: "admin", Name: owner + "-mini", Category: "OAuth", Type: "WeChatMiniProgram", ClientId: "mini-app", ClientSecret: "test-only"}
			official := &object.Provider{Owner: "admin", Name: owner + "-official", Category: "OAuth", Type: "WeChat", SubType: "Web", ClientId2: "official-app", ClientSecret2: "test-only", Content: "test-webhook-token"}
			for _, p := range []*object.Provider{mini, official} {
				if _, err := object.AddProvider(p); err != nil {
					t.Fatal(err)
				}
			}
			app := &object.Application{Owner: "admin", Name: owner, Organization: owner, ClientId: owner + "-client", ClientSecret: "test-only", EnableSignUp: true, TokenFormat: "JWT", GrantTypes: []string{"token"}, Cert: "cert-built-in", ExpireInHours: 1, Providers: []*object.ProviderItem{{Name: mini.Name, CanSignUp: true, CanSignIn: true, Provider: mini}, {Name: official.Name, CanSignUp: true, CanSignIn: true, Provider: official}}, SignupItems: []*object.SignupItem{{Name: "ID", Rule: "Random"}}}
			if _, err := object.AddApplication(app, "en"); err != nil {
				t.Fatal(err)
			}
			app, err = object.GetApplication(app.GetId())
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "concurrent" {
				db := probeDatabase(t)
				if _, err := db.Exec("CREATE TRIGGER wechat_signup_delay BEFORE INSERT ON `user` FOR EACH ROW DO SLEEP(0.2)"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { db.Exec("DROP TRIGGER IF EXISTS wechat_signup_delay") })
			}
			miniCode := "new-test-code"
			miniLogin := func() (string, error) {
				token, te, err := object.GetWechatMiniProgramToken(app, miniCode, "", false, "127.0.0.1:8000", "", "", "en")
				if err != nil {
					return "", err
				}
				if te != nil {
					return "", fmt.Errorf("mini token error: %s", te.ErrorDescription)
				}
				parsed, err := jwt.Parse(token.AccessToken, func(*jwt.Token) (interface{}, error) { return key, nil }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(app.ClientId), jwt.WithIssuer("http://127.0.0.1:8000"))
				if err != nil {
					return "", err
				}
				return parsed.Claims.GetSubject()
			}
			officialLogin := func() (string, error) {
				ticket := fmt.Sprintf("ticket-%s", scenario)
				vals := []string{official.Content, "123", "nonce"}
				sort.Strings(vals)
				hash := sha1.Sum([]byte(strings.Join(vals, "")))
				callback := server.URL + "/api/webhook?timestamp=123&nonce=nonce&signature=" + hex.EncodeToString(hash[:])
				xml := fmt.Sprintf("<xml><MsgType>event</MsgType><Event>SCAN</Event><EventKey>admin/%s</EventKey><FromUserName>official-open</FromUserName><Ticket>%s</Ticket></xml>", official.Name, ticket)
				if scenario == "official-subscribe" {
					xml = strings.ReplaceAll(strings.ReplaceAll(xml, "SCAN", "SUBSCRIBE"), "<EventKey>admin/", "<EventKey>qrscene_admin/")
				}
				res, err := http.Post(callback, "text/xml", strings.NewReader(xml))
				if err != nil {
					return "", err
				}
				b, _ := io.ReadAll(res.Body)
				res.Body.Close()
				if len(b) > 0 {
					return "", fmt.Errorf("callback: %s", b)
				}
				body, _ := json.Marshal(map[string]string{"application": app.Name, "organization": owner, "provider": official.Name, "code": "wechat_oa:" + ticket, "state": "casdoor", "method": "signin", "type": "token"})
				res, err = http.Post(server.URL+"/api/login?clientId="+url.QueryEscape(app.ClientId)+"&responseType=token", "application/json", bytes.NewReader(body))
				if err != nil {
					return "", err
				}
				defer res.Body.Close()
				var response struct {
					Status string
					Msg    string
					Data   json.RawMessage
				}
				if err = json.NewDecoder(res.Body).Decode(&response); err != nil {
					return "", err
				}
				if response.Status != "ok" {
					return "", fmt.Errorf("official login: %s", response.Msg)
				}
				var token string
				if err = json.Unmarshal(response.Data, &token); err != nil {
					return "", fmt.Errorf("official token response: %s", response.Data)
				}
				parsed, err := jwt.Parse(token, func(*jwt.Token) (interface{}, error) { return key, nil }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(app.ClientId), jwt.WithIssuer("http://127.0.0.1:8000"))
				if err != nil {
					return "", err
				}
				return parsed.Claims.GetSubject()
			}
			var first, second string
			var firstErr, secondErr error
			switch scenario {
			case "official-stale":
				first, firstErr = officialLogin()
				if firstErr != nil {
					t.Fatal(firstErr)
				}
				barrier := &userReadBarrier{owner: owner, sql: "wechat=?", reached: make(chan struct{}), resume: make(chan struct{})}
				barrier.armed.Store(true)
				registerProbeHook(t, barrier)
				var release sync.Once
				resume := func() { barrier.armed.Store(false); release.Do(func() { close(barrier.resume) }) }
				defer resume()
				staleDone := make(chan error, 1)
				go func() {
					subject, err := officialLogin()
					if err == nil && subject != first {
						err = fmt.Errorf("old login changed subject")
					}
					staleDone <- err
				}()
				select {
				case <-barrier.reached:
				case <-time.After(10 * time.Second):
					t.Fatal("official login did not reach its native user lookup")
				}
				officialUnion.Store(true)
				second, secondErr = officialLogin()
				resume()
				if err := <-staleDone; err != nil {
					t.Fatal(err)
				}
				if subject, err := miniLogin(); err != nil || subject != first {
					t.Fatalf("mini login after overlapping official writes: %v", err)
				}
			case "official-union-upgrade":
				first, firstErr = officialLogin()
				officialUnion.Store(true)
				second, secondErr = officialLogin()
				officialUnion.Store(false)
				withoutUnion, loginErr := officialLogin()
				if loginErr != nil || withoutUnion != first {
					t.Fatalf("official OpenID login changed after UnionID promotion: %v", loginErr)
				}
			case "different-union-case":
				first, firstErr = officialLogin()
				miniCode = "case-distinct"
				second, secondErr = miniLogin()
			case "mini-openid-only":
				miniCode = "no-union"
				first, firstErr = miniLogin()
				second, secondErr = miniLogin()
			case "union-upgrade":
				miniCode = "no-union"
				first, firstErr = miniLogin()
				miniCode = "new-test-code"
				promoted, promoteErr := miniLogin()
				if promoteErr != nil || promoted != first {
					t.Fatalf("identity promotion changed subject: %v", promoteErr)
				}
				second, secondErr = officialLogin()
			case "official-openid-only":
				first, firstErr = officialLogin()
				second, secondErr = officialLogin()
			case "mini-first", "official-subscribe":
				first, firstErr = miniLogin()
				second, secondErr = officialLogin()
			case "official-first":
				first, firstErr = officialLogin()
				second, secondErr = miniLogin()
				miniCode = "no-union"
				withoutUnion, loginErr := miniLogin()
				if loginErr != nil || withoutUnion != first {
					t.Fatalf("native mini OpenID login changed after official-first login: %v", loginErr)
				}
			default:
				var wg sync.WaitGroup
				wg.Add(2)
				go func() { defer wg.Done(); first, firstErr = miniLogin() }()
				go func() { defer wg.Done(); second, secondErr = officialLogin() }()
				wg.Wait()
			}
			if firstErr != nil || secondErr != nil {
				t.Fatalf("login errors: %v / %v", firstErr, secondErr)
			}
			if scenario == "different-union-case" {
				if first == "" || second == "" || first == second || probeAccountCount(t, owner) != 2 {
					t.Fatal("different UnionIDs were treated as the same user")
				}
				return
			}
			if first == "" || first != second {
				t.Fatalf("different token subjects: %q / %q", first, second)
			}
			count, err := object.GetUserCount(owner, "", "", "")
			if err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatalf("users=%d, want 1", count)
			}
			expectedIdentity := "same-real-union"
			if scenario == "official-openid-only" {
				expectedIdentity = "official-open"
			}
			if scenario == "mini-openid-only" {
				expectedIdentity = "mini-open"
			}
			var user *object.User
			if scenario == "official-openid-only" || scenario == "mini-openid-only" {
				user, err = object.GetUserByField(owner, "WeChat", expectedIdentity)
			} else {
				user, err = object.GetUserByWechatUnionId(owner, expectedIdentity)
			}
			if err != nil {
				t.Fatal(err)
			}
			if user == nil || user.Id != first {
				t.Fatal("persisted identity differs from token")
			}
			if scenario == "mini-first" || scenario == "union-upgrade" || scenario == "official-first" {
				if user.WeChat != "mini-open" || user.Properties[object.UserPropertiesWechatUnionId] != "same-real-union" {
					t.Fatal("UnionID matching changed native mini-program OpenID storage")
				}
			}
			if scenario == "official-union-upgrade" && user.WeChat != "official-open" {
				t.Fatal("UnionID promotion changed the native official OpenID")
			}
		})
	}
}
