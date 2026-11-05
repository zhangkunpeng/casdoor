package idp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type officialAccountTransport struct {
	base   http.RoundTripper
	target string
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
				case "/cgi-bin/stable_token":
					var fields map[string]any
					if json.NewDecoder(r.Body).Decode(&fields) != nil ||
						fields["appid"] != "official-app" || fields["secret"] != "test-secret" ||
						fields["force_refresh"] != false || r.Method != http.MethodPost {
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
			client := &http.Client{Transport: officialAccountTransport{http.DefaultTransport, server.URL}}
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
