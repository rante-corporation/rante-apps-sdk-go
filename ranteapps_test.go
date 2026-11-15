package ranteapps

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func newVerifier(t *testing.T, login *localLogin, change func(*Config)) *Verifier {
	t.Helper()
	cfg := Config{ClientID: loadCases(t).ClientID, Authority: login.origin}
	if change != nil {
		change(&cfg)
	}
	v, err := NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func validToken(t *testing.T, login *localLogin, claims map[string]any, sign string) string {
	t.Helper()
	testCase := map[string]any{}
	if claims != nil {
		testCase["claims"] = claims
	}
	if sign != "" {
		testCase["sign"] = sign
	}
	return login.buildToken(t, loadCases(t), testCase, time.Now().Unix())
}

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestTheOptionsAreChecked(t *testing.T) {
	client := "3f2b8c1e-7d4a-4e9b-a6c5-1d2e3f4a5b6c"
	bad := []Config{
		{ClientID: "contoso-app"},
		{ClientID: client, Authority: "http://login.example.com"},
		{ClientID: client, Authority: "https://login.example.com/tenant"},
		{ClientID: client, Algorithms: []string{"HS256"}},
		{ClientID: client, Algorithms: []string{}},
		{ClientID: client, Tenants: []string{"contoso"}},
		{ClientID: client, ClockSkew: time.Hour},
		{ClientID: client, RequiredScopes: []string{"two words"}},
	}
	for i, cfg := range bad {
		if _, err := NewVerifier(cfg); code(err) != "invalid_configuration" {
			t.Errorf("case %d: got %v", i, err)
		}
	}
	v, err := NewVerifier(Config{ClientID: "3F2B8C1E-7D4A-4E9B-A6C5-1D2E3F4A5B6C"})
	if err != nil || v.ClientID() != client || v.Authority() != DefaultAuthority {
		t.Fatalf("defaults: %v %v", v, err)
	}
	local, err := NewVerifier(Config{ClientID: client, Authority: "http://localhost:8080/"})
	if err != nil || local.Authority() != "http://localhost:8080" {
		t.Fatalf("local authority: %v", err)
	}
	if FrameAncestors != "frame-ancestors https://portal.rante.com" {
		t.Fatal(FrameAncestors)
	}
}

func TestBearerToken(t *testing.T) {
	cases := map[string]string{
		"Bearer abc.def.ghi":      "abc.def.ghi",
		"bearer   abc.def-_~+/=":  "abc.def-_~+/=",
		"":                        "",
		"Basic dXNlcjpwYXNz":      "",
		"Bearer":                  "",
		"Bearer a b":              "",
		"Bearer a,b":              "",
	}
	for header, want := range cases {
		if got := BearerToken(header); got != want {
			t.Errorf("%q: got %q, want %q", header, got, want)
		}
	}
}

func TestErrorsCarryStatusAndWWWAuthenticate(t *testing.T) {
	if got := (&Error{Code: "missing_token"}).WWWAuthenticate(); got != "Bearer" {
		t.Error(got)
	}
	if got := (&Error{Code: "token_expired", Message: `The "token" expired.`}).WWWAuthenticate(); got != `Bearer error="invalid_token", error_description="The 'token' expired."` {
		t.Error(got)
	}
	scope := &Error{Code: "insufficient_scope", RequiredScopes: []string{"user.read", "auth.token"}}
	if scope.Status() != 403 || scope.WWWAuthenticate() != `Bearer error="insufficient_scope", scope="user.read auth.token"` {
		t.Error(scope.WWWAuthenticate())
	}
	if (&Error{Code: "tenant_not_allowed"}).WWWAuthenticate() != "" || (&Error{Code: "network_error"}).Status() != 503 {
		t.Error("tenant_not_allowed / network_error")
	}
}

func TestTheConfigurationAndKeysAreFetchedOnce(t *testing.T) {
	login := startLocalLogin(t)
	v := newVerifier(t, login, nil)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		token := validToken(t, login, nil, "")
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Verify(context.Background(), token); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if login.discoveryCount.Load() != 1 || login.jwksCount.Load() != 1 {
		t.Fatalf("fetched %d / %d times", login.discoveryCount.Load(), login.jwksCount.Load())
	}
}

func TestAnUnknownKidDoesNotRefetchDuringTheCooldown(t *testing.T) {
	login := startLocalLogin(t)
	v := newVerifier(t, login, nil)
	if _, err := v.Verify(context.Background(), validToken(t, login, nil, "")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		token := login.buildToken(t, loadCases(t), map[string]any{"header": map[string]any{"kid": "made-up"}}, time.Now().Unix())
		if _, err := v.Verify(context.Background(), token); code(err) != "invalid_token" {
			t.Fatal(err)
		}
	}
	if login.jwksCount.Load() != 1 {
		t.Fatalf("keys fetched %d times", login.jwksCount.Load())
	}
}

func TestANewKeyIsPickedUp(t *testing.T) {
	login := startLocalLogin(t)
	v := newVerifier(t, login, func(c *Config) { c.JWKSCooldown = -1 })
	if _, err := v.Verify(context.Background(), validToken(t, login, nil, "")); err != nil {
		t.Fatal(err)
	}
	login.publishSecondKey()
	p, err := v.Verify(context.Background(), validToken(t, login, nil, "key-2"))
	if err != nil || p.TenantID != loadCases(t).TenantID {
		t.Fatalf("%v %v", p, err)
	}
}

func TestES256IsAcceptedWhenAllowed(t *testing.T) {
	login := startLocalLogin(t)
	v := newVerifier(t, login, func(c *Config) { c.Algorithms = []string{"RS256", "ES256"} })
	p, err := v.Verify(context.Background(), validToken(t, login, nil, "es256"))
	if err != nil || p.UserID != loadCases(t).UserID {
		t.Fatalf("%v %v", p, err)
	}
}

func TestThePrincipalCarriesTheClaims(t *testing.T) {
	login := startLocalLogin(t)
	v := newVerifier(t, login, nil)
	p, err := v.Verify(context.Background(), validToken(t, login, map[string]any{"roles": []any{"Reader", 7}, "email": "ada@example.com"}, ""))
	if err != nil {
		t.Fatal(err)
	}
	if p.AppID != loadCases(t).ClientID || len(p.Roles) != 1 || p.Roles[0] != "Reader" || p.Email != "ada@example.com" {
		t.Fatalf("%+v", p)
	}
	if !p.ExpiresAt.After(time.Now()) || p.IssuedAt.IsZero() || p.Claims["ver"] != "2.0" {
		t.Fatalf("%+v", p)
	}
}

func TestRepeatedClaimsAreRefused(t *testing.T) {
	login := startLocalLogin(t)
	v := newVerifier(t, login, nil)
	if err := checkDuplicateKeys([]byte(`{"aud":"a","aud":"b"}`)); code(err) != "invalid_token" {
		t.Fatal(err)
	}
	if err := checkDuplicateKeys([]byte(`{"aud":"a","x":{"aud":"b"}}`)); err != nil {
		t.Fatal(err)
	}
	_ = v
}

func TestDiscoveryProblemsAreReported(t *testing.T) {
	login := startLocalLogin(t)
	token := validToken(t, login, nil, "")
	login.mode.Store("not-found")
	if _, err := newVerifier(t, login, nil).Verify(context.Background(), token); code(err) != "discovery_failed" {
		t.Fatal(err)
	}
	login.mode.Store("other-issuer")
	if _, err := newVerifier(t, login, nil).Verify(context.Background(), token); code(err) != "discovery_failed" {
		t.Fatal(err)
	}
	closed := httptest.NewServer(http.NotFoundHandler())
	address := closed.URL
	closed.Close()
	down, err := NewVerifier(Config{ClientID: loadCases(t).ClientID, Authority: address})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := down.Verify(context.Background(), token); code(err) != "network_error" {
		t.Fatal(err)
	}
}

func TestAFailedFetchIsRetried(t *testing.T) {
	login := startLocalLogin(t)
	v := newVerifier(t, login, nil)
	token := validToken(t, login, nil, "")
	login.mode.Store("not-found")
	if _, err := v.Verify(context.Background(), token); code(err) != "discovery_failed" {
		t.Fatal(err)
	}
	login.mode.Store("ok")
	if _, err := v.Verify(context.Background(), token); err != nil {
		t.Fatal(err)
	}
}

func TestMiddleware(t *testing.T) {
	login := startLocalLogin(t)
	v := newVerifier(t, login, func(c *Config) { c.RequiredScopes = []string{"user.read"} })
	handler := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := PrincipalFromContext(r.Context())
		if !ok {
			t.Error("no principal")
		}
		_, _ = w.Write([]byte(p.UserID))
	}))

	request := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	request.Header.Set("Authorization", "Bearer "+validToken(t, login, nil, ""))
	ok := httptest.NewRecorder()
	handler.ServeHTTP(ok, request)
	if ok.Code != 200 || ok.Body.String() != loadCases(t).UserID {
		t.Fatalf("%d %s", ok.Code, ok.Body.String())
	}

	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/api/me", nil))
	var body map[string]string
	_ = json.Unmarshal(missing.Body.Bytes(), &body)
	if missing.Code != 401 || missing.Header().Get("WWW-Authenticate") != "Bearer" || body["error"] != "missing_token" {
		t.Fatalf("%d %v", missing.Code, body)
	}

	noScope := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	noScope.Header.Set("Authorization", "Bearer "+validToken(t, login, map[string]any{"scp": "tenant.read"}, ""))
	forbidden := httptest.NewRecorder()
	handler.ServeHTTP(forbidden, noScope)
	if forbidden.Code != 403 {
		t.Fatalf("%d", forbidden.Code)
	}
}
