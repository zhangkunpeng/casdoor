package idp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type officialAccountTransport struct {
	base   http.RoundTripper
	target string
}

func TestResolveWechatOfficialAccountIdentityTimeout(t *testing.T) {
	for _, path := range []string{"/cgi-bin/token", "/cgi-bin/user/info"} {
		t.Run(path, func(t *testing.T) {
			gate := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == path {
					select {
					case <-r.Context().Done():
						return
					case <-gate:
					}
				}
				if r.URL.Path == "/cgi-bin/token" {
					fmt.Fprint(w, `{"access_token":"test-token"}`)
				} else {
					fmt.Fprint(w, `{"openid":"official-open"}`)
				}
			}))
			defer server.Close()
			base := http.DefaultTransport
			transport := officialAccountTransport{base, server.URL}
			http.DefaultTransport = transport
			t.Cleanup(func() { http.DefaultTransport = base })
			done := make(chan error, 1)
			go func() {
				_, err := ResolveWechatOfficialAccountIdentity(&http.Client{Transport: transport, Timeout: 30 * time.Millisecond},
					"official-app", "test-secret", "official-open")
				done <- err
			}()
			select {
			case err := <-done:
				close(gate)
				if err == nil {
					t.Fatal("slow WeChat request succeeded")
				}
			case <-time.After(time.Second):
				close(gate)
				<-done
				t.Fatal("WeChat request ignored the supplied client timeout")
			}
		})
	}
}

func (r officialAccountTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	copy := req.Clone(req.Context())
	target, _ := http.NewRequest(req.Method, r.target, nil)
	copy.URL.Scheme, copy.URL.Host = target.URL.Scheme, target.URL.Host
	return r.base.RoundTrip(copy)
}

func TestResolveWechatOfficialAccountIdentity(t *testing.T) {
	for _, test := range []struct {
		name, token, user string
		status            int
		wantError         bool
	}{
		{"union id", `{"access_token":"test-token","expires_in":7200}`, `{"openid":"official-open","unionid":"shared-union","subscribe":1}`, 200, false},
		{"no union id", `{"access_token":"test-token","expires_in":7200}`, `{"openid":"official-open"}`, 200, false},
		{"different user", `{"access_token":"test-token","expires_in":7200}`, `{"openid":"other-open","unionid":"shared-union"}`, 200, true},
		{"api denied", `{"access_token":"test-token","expires_in":7200}`, `{"errcode":48001,"errmsg":"api unauthorized"}`, 200, true},
		{"token denied", `{"errcode":40164,"errmsg":"invalid ip"}`, `{}`, 200, true},
		{"bad json", `{"access_token":"test-token","expires_in":7200}`, `{`, 200, true},
		{"http failure", `{"access_token":"test-token","expires_in":7200}`, `{}`, 503, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/cgi-bin/token":
					if r.URL.Query().Get("appid") != "official-app" ||
						r.URL.Query().Get("secret") != "test-secret" || r.Method != http.MethodGet {
						t.Error("wrong account credentials")
					}
					fmt.Fprint(w, test.token)
				case "/cgi-bin/user/info":
					if r.URL.Query().Get("openid") != "official-open" || r.URL.Query().Get("access_token") != "test-token" {
						t.Error("wrong user lookup")
					}
					w.WriteHeader(test.status)
					fmt.Fprint(w, test.user)
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			base := http.DefaultTransport
			http.DefaultTransport = officialAccountTransport{base, server.URL}
			t.Cleanup(func() { http.DefaultTransport = base })
			client := &http.Client{}
			user, err := ResolveWechatOfficialAccountIdentity(client, "official-app", "test-secret", "official-open")
			if (err != nil) != test.wantError {
				t.Fatalf("error=%v, wantError=%v", err, test.wantError)
			}
			if !test.wantError && (user.Openid != "official-open" || (test.name == "union id" && user.Unionid != "shared-union")) {
				t.Fatalf("incorrect identity: %#v", user)
			}
		})
	}
}
