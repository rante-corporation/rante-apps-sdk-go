// Package ranteapps checks the access tokens that Rante.getAccessToken() gives a Rante app's frontend, as described in
// docs/tokens.md of github.com/rante-corporation/rante-apps-sdk. Signatures are checked with go-jose.
package ranteapps

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	// Version is the SDK version.
	Version = "0.1.0"
	// DefaultAuthority is Rante Login, which issues app access tokens.
	DefaultAuthority = "https://login.rante.com"
	// FrameAncestors is the Content-Security-Policy directive an external app's pages send so that only Rante can
	// frame them.
	FrameAncestors = "frame-ancestors https://portal.rante.com"
)

var (
	guidPattern   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	jwtPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$`)
	bearerPattern = regexp.MustCompile(`(?i)^Bearer +([A-Za-z0-9\-._~+/]+=*)$`)
	statuses      = map[string]int{
		"missing_token":         401,
		"invalid_token":         401,
		"token_expired":         401,
		"tenant_not_allowed":    403,
		"insufficient_scope":    403,
		"discovery_failed":      503,
		"network_error":         503,
		"invalid_configuration": 500,
	}
	localHosts = []string{"localhost", "127.0.0.1", "::1"}
)

// Error is every failure, with a stable code (docs/tokens.md) and the HTTP status to answer with.
type Error struct {
	// Code is missing_token, invalid_token, token_expired, tenant_not_allowed, insufficient_scope, discovery_failed,
	// network_error or invalid_configuration.
	Code    string
	Message string
	// RequiredScopes are the scopes the verifier requires (for insufficient_scope).
	RequiredScopes []string
	Err            error
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Unwrap returns the underlying error, if any.
func (e *Error) Unwrap() error { return e.Err }

// Status is the HTTP status to answer with.
func (e *Error) Status() int {
	if s, ok := statuses[e.Code]; ok {
		return s
	}
	return 500
}

// WWWAuthenticate is the WWW-Authenticate header value for this error (RFC 6750), or "" when none applies.
func (e *Error) WWWAuthenticate() string {
	switch e.Code {
	case "missing_token":
		return "Bearer"
	case "invalid_token", "token_expired":
		return `Bearer error="invalid_token", error_description="` + headerText(e.Message) + `"`
	case "insufficient_scope":
		return `Bearer error="insufficient_scope", scope="` + headerText(strings.Join(e.RequiredScopes, " ")) + `"`
	}
	return ""
}

func headerText(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\'')
		case r < ' ' || r > '~':
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func invalid(message string, err error) *Error {
	return &Error{Code: "invalid_token", Message: message, Err: err}
}

func configError(message string) *Error {
	return &Error{Code: "invalid_configuration", Message: message}
}

// Config holds a verifier's options. Zero values mean the defaults.
type Config struct {
	// ClientID is your app's Application (client) ID. Required.
	ClientID string
	// Tenants, when set, are the only tenants whose tokens are accepted.
	Tenants []string
	// RequiredScopes are scopes every token must have (from its scp claim).
	RequiredScopes []string
	// ExtraAudiences are audiences accepted besides the client ID, such as api://{clientId}.
	ExtraAudiences []string
	// Authority defaults to https://login.rante.com. http is accepted for localhost only, for tests.
	Authority string
	// ClockSkew is the clock difference tolerated for exp, nbf and iat. 0 means 60 seconds; negative means none.
	ClockSkew time.Duration
	// Algorithms defaults to RS256. RS256 and ES256 are supported.
	Algorithms []string
	// Timeout of each request to Rante Login. 0 means 5 seconds.
	Timeout time.Duration
	// JWKSCooldown is the minimum time between two key fetches (an unknown kid triggers one). 0 means 30 seconds;
	// negative means none.
	JWKSCooldown time.Duration
	// JWKSMaxAge is how long fetched keys are used before they are fetched again. 0 means 10 minutes.
	JWKSMaxAge time.Duration
	// HTTPClient is used for Rante Login (for proxies or tests). nil means a client of its own.
	HTTPClient *http.Client
}

// Principal is who a verified token is for.
type Principal struct {
	UserID          string // the person's object ID in the tenant (oid)
	TenantID        string // the tenant (tid)
	Subject         string // the person's subject for this app (sub): stable, different for every app
	Name            string
	Username        string // preferred_username
	Email           string
	AppID           string // your client ID
	AuthorizedParty string // azp: the client that asked for the token on the person's behalf
	Scopes          []string
	Roles           []string
	IssuedAt        time.Time // zero when the token has no iat
	ExpiresAt       time.Time
	Issuer          string
	Claims          map[string]any // every claim; numbers are json.Number
}

type keySnapshot struct {
	keys      map[string]*jose.JSONWebKey
	fetchedAt time.Time
}

// Verifier checks Rante app access tokens for one app. Create one per app and reuse it: it caches Rante Login's
// signing keys. It is safe for concurrent use.
type Verifier struct {
	clientID       string
	audiences      []string
	authority      string
	tenants        []string
	requiredScopes []string
	clockSkew      time.Duration
	algorithms     []jose.SignatureAlgorithm
	timeout        time.Duration
	jwksCooldown   time.Duration
	jwksMaxAge     time.Duration
	http           *http.Client

	mu       sync.Mutex
	snapshot atomic.Pointer[keySnapshot]
	jwksURI  string
}

// NewVerifier checks the configuration and returns a verifier. Errors are *Error with code invalid_configuration.
func NewVerifier(cfg Config) (*Verifier, error) {
	if !guidPattern.MatchString(cfg.ClientID) {
		return nil, configError("ClientID must be your app's Application (client) ID, a GUID.")
	}
	v := &Verifier{clientID: strings.ToLower(cfg.ClientID)}
	v.audiences = []string{v.clientID}
	for _, a := range cfg.ExtraAudiences {
		if a == "" {
			return nil, configError("ExtraAudiences has an empty entry.")
		}
		v.audiences = append(v.audiences, strings.ToLower(a))
	}
	authority := cfg.Authority
	if authority == "" {
		authority = DefaultAuthority
	}
	normalized, err := normalizeAuthority(authority)
	if err != nil {
		return nil, err
	}
	v.authority = normalized
	for _, t := range cfg.Tenants {
		if !guidPattern.MatchString(t) {
			return nil, configError(fmt.Sprintf("Tenants has an invalid entry: %q.", t))
		}
		v.tenants = append(v.tenants, strings.ToLower(t))
	}
	for _, s := range cfg.RequiredScopes {
		if s == "" || strings.ContainsAny(s, " \t\r\n") {
			return nil, configError(fmt.Sprintf("RequiredScopes has an invalid entry: %q.", s))
		}
		v.requiredScopes = append(v.requiredScopes, s)
	}
	switch {
	case cfg.ClockSkew == 0:
		v.clockSkew = 60 * time.Second
	case cfg.ClockSkew < 0:
		v.clockSkew = 0
	case cfg.ClockSkew > 10*time.Minute:
		return nil, configError("ClockSkew must be at most 10 minutes.")
	default:
		v.clockSkew = cfg.ClockSkew
	}
	algorithms := cfg.Algorithms
	if len(algorithms) == 0 {
		if cfg.Algorithms != nil {
			return nil, configError("Algorithms must be a non-empty subset of RS256, ES256.")
		}
		algorithms = []string{"RS256"}
	}
	for _, a := range algorithms {
		if a != "RS256" && a != "ES256" {
			return nil, configError("Algorithms must be a non-empty subset of RS256, ES256.")
		}
		v.algorithms = append(v.algorithms, jose.SignatureAlgorithm(a))
	}
	v.timeout = orDefault(cfg.Timeout, 5*time.Second)
	switch {
	case cfg.JWKSCooldown == 0:
		v.jwksCooldown = 30 * time.Second
	case cfg.JWKSCooldown < 0:
		v.jwksCooldown = 0
	default:
		v.jwksCooldown = cfg.JWKSCooldown
	}
	v.jwksMaxAge = orDefault(cfg.JWKSMaxAge, 10*time.Minute)
	v.http = cfg.HTTPClient
	if v.http == nil {
		v.http = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return v, nil
}

func orDefault(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}

func isLocal(host string) bool {
	return slices.Contains(localHosts, strings.ToLower(host))
}

func normalizeAuthority(value string) (string, *Error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", configError("Authority must be an absolute URL such as https://login.rante.com.")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && !(scheme == "http" && isLocal(u.Hostname())) {
		return "", configError("Authority must use https (http is accepted only for localhost, for tests).")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", configError("Authority is an origin only, such as https://login.rante.com.")
	}
	return scheme + "://" + strings.ToLower(u.Host), nil
}

// ClientID is your client ID, in lower case.
func (v *Verifier) ClientID() string { return v.clientID }

// Authority is the authority, such as https://login.rante.com.
func (v *Verifier) Authority() string { return v.authority }

// Verify checks a raw JWT (without "Bearer ") and returns who it is for. Errors are *Error.
func (v *Verifier) Verify(ctx context.Context, token string) (*Principal, error) {
	if token == "" {
		return nil, &Error{Code: "missing_token", Message: "No access token was sent."}
	}
	if len(token) > 16384 || !jwtPattern.MatchString(token) {
		return nil, invalid("The access token is not a JSON Web Token.", nil)
	}
	jws, err := jose.ParseSignedCompact(token, v.algorithms)
	if err != nil {
		return nil, invalid("The access token cannot be read, or its algorithm is not accepted.", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, invalid("The access token must have exactly one signature.", nil)
	}
	header := jws.Signatures[0].Protected
	if header.KeyID == "" {
		return nil, invalid("The access token names no signing key (kid).", nil)
	}
	key, kerr := v.signingKey(ctx, header.KeyID)
	if kerr != nil {
		return nil, kerr
	}
	if key.Algorithm != "" && key.Algorithm != header.Algorithm {
		return nil, invalid("The access token's algorithm does not match its signing key.", nil)
	}
	payload, err := jws.Verify(key.Key)
	if err != nil {
		return nil, invalid("The access token signature is not valid.", err)
	}
	return v.principal(payload)
}

func (v *Verifier) principal(payload []byte) (*Principal, error) {
	if err := checkDuplicateKeys(payload); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var claims map[string]any
	if err := decoder.Decode(&claims); err != nil || claims == nil {
		return nil, invalid("The access token payload is not a JSON object.", err)
	}
	now := float64(time.Now().Unix())
	skew := v.clockSkew.Seconds()
	exp, ok := number(claims["exp"])
	if !ok {
		return nil, invalid("The access token has no expiry (exp).", nil)
	}
	if exp <= now-skew {
		return nil, &Error{Code: "token_expired", Message: "The access token has expired."}
	}
	if raw, present := claims["nbf"]; present {
		if nbf, ok := number(raw); !ok || nbf > now+skew {
			return nil, invalid("The access token is not valid yet (nbf).", nil)
		}
	}
	iat, hasIat := 0.0, false
	if raw, present := claims["iat"]; present {
		value, ok := number(raw)
		if !ok || value > now+skew {
			return nil, invalid("The access token was issued in the future (iat).", nil)
		}
		iat, hasIat = value, true
	}
	tid, _ := claims["tid"].(string)
	if !guidPattern.MatchString(tid) {
		return nil, invalid("The access token names no valid tenant (tid).", nil)
	}
	tenantID := strings.ToLower(tid)
	iss, _ := claims["iss"].(string)
	if !strings.EqualFold(iss, v.authority+"/"+tenantID+"/v2.0") {
		return nil, invalid("The access token was not issued by Rante Login for its tenant (iss).", nil)
	}
	if !v.audienceMatches(claims["aud"]) {
		return nil, invalid("The access token was issued for another app (aud).", nil)
	}
	oid, _ := claims["oid"].(string)
	if !guidPattern.MatchString(oid) {
		return nil, invalid("The access token names no person (oid).", nil)
	}
	if raw, present := claims["idtyp"]; present && raw != "user" {
		return nil, invalid("The access token is not a person's token (idtyp).", nil)
	}
	if v.tenants != nil && !slices.Contains(v.tenants, tenantID) {
		return nil, &Error{Code: "tenant_not_allowed", Message: "This tenant may not use this app."}
	}
	scopes := []string{}
	if scp, ok := claims["scp"].(string); ok {
		scopes = strings.Fields(scp)
	}
	var missing []string
	for _, s := range v.requiredScopes {
		if !slices.Contains(scopes, s) {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		plural := ""
		if len(missing) > 1 {
			plural = "s"
		}
		return nil, &Error{Code: "insufficient_scope", Message: "The access token lacks the scope" + plural + " " + strings.Join(missing, ", ") + ".",
			RequiredScopes: slices.Clone(v.requiredScopes)}
	}
	roles := []string{}
	if list, ok := claims["roles"].([]any); ok {
		for _, r := range list {
			if s, ok := r.(string); ok {
				roles = append(roles, s)
			}
		}
	}
	p := &Principal{
		UserID:          strings.ToLower(oid),
		TenantID:        tenantID,
		Subject:         text(claims, "sub"),
		Name:            text(claims, "name"),
		Username:        text(claims, "preferred_username"),
		Email:           text(claims, "email"),
		AppID:           v.clientID,
		AuthorizedParty: text(claims, "azp"),
		Scopes:          scopes,
		Roles:           roles,
		ExpiresAt:       time.Unix(int64(exp), 0).UTC(),
		Issuer:          iss,
		Claims:          claims,
	}
	if hasIat {
		p.IssuedAt = time.Unix(int64(iat), 0).UTC()
	}
	return p, nil
}

func (v *Verifier) audienceMatches(aud any) bool {
	switch value := aud.(type) {
	case string:
		return slices.Contains(v.audiences, strings.ToLower(value))
	case []any:
		for _, item := range value {
			if s, ok := item.(string); ok && slices.Contains(v.audiences, strings.ToLower(s)) {
				return true
			}
		}
	}
	return false
}

func number(value any) (float64, bool) {
	n, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
}

func text(claims map[string]any, name string) string {
	s, _ := claims[name].(string)
	return s
}

// checkDuplicateKeys refuses a payload that names a top-level claim twice: JSON parsers disagree on which value wins.
func checkDuplicateKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return invalid("The access token payload is not a JSON object.", err)
	}
	seen := map[string]bool{}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return invalid("The access token payload is not valid JSON.", err)
		}
		name, _ := key.(string)
		if seen[name] {
			return invalid("The access token repeats the claim "+name+".", nil)
		}
		seen[name] = true
		var skip json.RawMessage
		if err := decoder.Decode(&skip); err != nil {
			return invalid("The access token payload is not valid JSON.", err)
		}
	}
	return nil
}

// ------------------------------------------------------------------------------------------------ keys

func (v *Verifier) signingKey(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	if s := v.snapshot.Load(); s != nil && time.Since(s.fetchedAt) <= v.jwksMaxAge {
		if key, ok := s.keys[kid]; ok {
			return key, nil
		}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	s := v.snapshot.Load()
	stale := s == nil || time.Since(s.fetchedAt) > v.jwksMaxAge
	if stale || (s.keys[kid] == nil && time.Since(s.fetchedAt) >= v.jwksCooldown) {
		fresh, err := v.fetchKeys(ctx)
		if err != nil {
			return nil, err
		}
		v.snapshot.Store(fresh)
		s = fresh
	}
	key, ok := s.keys[kid]
	if !ok {
		return nil, invalid("No signing key of Rante Login matches the access token.", nil)
	}
	return key, nil
}

func (v *Verifier) fetchKeys(ctx context.Context) (*keySnapshot, error) {
	if v.jwksURI == "" {
		body, err := v.get(ctx, v.authority+"/common/v2.0/.well-known/openid-configuration", "discovery_failed", "Rante Login's OpenID configuration")
		if err != nil {
			return nil, err
		}
		var metadata struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		if err := json.Unmarshal(body, &metadata); err != nil {
			return nil, &Error{Code: "discovery_failed", Message: "Rante Login's OpenID configuration is not JSON.", Err: err}
		}
		if metadata.Issuer != v.authority+"/common/v2.0" {
			return nil, &Error{Code: "discovery_failed", Message: "Rante Login's OpenID configuration names another issuer."}
		}
		u, err := url.Parse(metadata.JWKSURI)
		if err != nil || !(u.Scheme == "https" || (u.Scheme == "http" && isLocal(u.Hostname()))) {
			return nil, &Error{Code: "discovery_failed", Message: "Rante Login's OpenID configuration has no valid https jwks_uri."}
		}
		v.jwksURI = metadata.JWKSURI
	}
	body, err := v.get(ctx, v.jwksURI, "network_error", "Rante Login's signing keys")
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, &Error{Code: "network_error", Message: "Rante Login's signing keys are not a JSON Web Key Set.", Err: err}
	}
	keys := map[string]*jose.JSONWebKey{}
	for _, raw := range set.Keys {
		var key jose.JSONWebKey
		if err := key.UnmarshalJSON(raw); err != nil {
			continue // a key type this SDK does not use
		}
		if key.KeyID == "" || (key.Use != "" && key.Use != "sig") || !key.IsPublic() {
			continue
		}
		if _, dup := keys[key.KeyID]; !dup {
			k := key
			keys[key.KeyID] = &k
		}
	}
	return &keySnapshot{keys: keys, fetchedAt: time.Now()}, nil
}

func (v *Verifier) get(ctx context.Context, address, failureCode, what string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, &Error{Code: failureCode, Message: what + " has an invalid address.", Err: err}
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.http.Do(req)
	if err != nil {
		var netErr net.Error
		message := what + " could not be fetched."
		if errors.As(err, &netErr) && netErr.Timeout() {
			message = what + " could not be fetched in time."
		}
		return nil, &Error{Code: "network_error", Message: message, Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &Error{Code: failureCode, Message: fmt.Sprintf("%s answered %d.", what, resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, &Error{Code: "network_error", Message: what + " could not be read.", Err: err}
	}
	return body, nil
}

// ------------------------------------------------------------------------------------------------ HTTP helpers

// BearerToken returns the token of an Authorization header value ("Bearer <token>"), or "" when there is none.
func BearerToken(header string) string {
	m := bearerPattern.FindStringSubmatch(strings.TrimSpace(header))
	if m == nil {
		return ""
	}
	return m[1]
}

type contextKey struct{}

// Middleware verifies the request's bearer token and passes the principal in the request context (see
// PrincipalFromContext); it answers 401/403/503 with a JSON body {"error","message"} and WWW-Authenticate otherwise.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := v.Verify(r.Context(), BearerToken(r.Header.Get("Authorization")))
		if err != nil {
			WriteError(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, principal)))
	})
}

// PrincipalFromContext returns the principal Middleware stored in a request context.
func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(contextKey{}).(*Principal)
	return p, ok
}

// WriteError writes an error as JSON with its status and WWW-Authenticate header (500 for errors that are not *Error).
func WriteError(w http.ResponseWriter, err error) {
	var e *Error
	if !errors.As(err, &e) {
		e = &Error{Code: "server_error", Message: "The request could not be completed."}
	}
	if challenge := e.WWWAuthenticate(); challenge != "" {
		w.Header().Set("WWW-Authenticate", challenge)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(e.Status())
	_ = json.NewEncoder(w).Encode(map[string]string{"error": e.Code, "message": e.Message})
}
