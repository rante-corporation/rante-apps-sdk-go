package ranteapps

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// localLogin is a stand-in for Rante Login's key publishing, for the tests: the OpenID configuration and the JWKS on
// 127.0.0.1, with keys generated for the run, plus a signer that builds the tokens of conformance/tokens.json.
type localLogin struct {
	server         *httptest.Server
	origin         string
	rsa1           *rsa.PrivateKey
	rsa2           *rsa.PrivateKey
	rsaOther       *rsa.PrivateKey
	ec1            *ecdsa.PrivateKey
	mu             sync.Mutex
	published      []map[string]string
	discoveryCount atomic.Int32
	jwksCount      atomic.Int32
	mode           atomic.Value // "ok", "not-found" or "other-issuer"
}

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func rsaJWK(key *rsa.PrivateKey, kid string) map[string]string {
	return map[string]string{"kty": "RSA", "n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()), "kid": kid, "alg": "RS256", "use": "sig"}
}

func ecJWK(key *ecdsa.PrivateKey, kid string) map[string]string {
	return map[string]string{"kty": "EC", "crv": "P-256", "x": b64(key.X.FillBytes(make([]byte, 32))), "y": b64(key.Y.FillBytes(make([]byte, 32))),
		"kid": kid, "alg": "ES256", "use": "sig"}
}

func startLocalLogin(t *testing.T) *localLogin {
	t.Helper()
	newRSA := func() *rsa.PrivateKey {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	l := &localLogin{rsa1: newRSA(), rsa2: newRSA(), rsaOther: newRSA(), ec1: ec}
	l.published = []map[string]string{rsaJWK(l.rsa1, "key-1"), ecJWK(l.ec1, "ec-1")}
	l.mode.Store("ok")
	mux := http.NewServeMux()
	mux.HandleFunc("/common/v2.0/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		l.discoveryCount.Add(1)
		switch l.mode.Load() {
		case "not-found":
			http.NotFound(w, r)
			return
		case "other-issuer":
			writeJSON(w, map[string]string{"issuer": "https://evil.example/common/v2.0", "jwks_uri": "https://evil.example/keys"})
			return
		}
		writeJSON(w, map[string]string{"issuer": l.origin + "/common/v2.0", "jwks_uri": l.origin + "/common/discovery/v2.0/keys"})
	})
	mux.HandleFunc("/common/discovery/v2.0/keys", func(w http.ResponseWriter, r *http.Request) {
		l.jwksCount.Add(1)
		l.mu.Lock()
		keys := append([]map[string]string(nil), l.published...)
		l.mu.Unlock()
		writeJSON(w, map[string]any{"keys": keys})
	})
	l.server = httptest.NewServer(mux)
	l.origin = l.server.URL
	t.Cleanup(l.server.Close)
	return l
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func (l *localLogin) publishSecondKey() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.published = append(l.published, rsaJWK(l.rsa2, "key-2"))
}

func publicKeyPEM(key *rsa.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// token signs header + claims. how: key-1 | key-2 | other-key | es256 | hs256-public-key | none.
func (l *localLogin) token(t *testing.T, header, claims map[string]any, how string) string {
	t.Helper()
	head := map[string]any{}
	for k, v := range header {
		head[k] = v
	}
	switch how {
	case "es256":
		head["alg"], head["kid"] = "ES256", "ec-1"
	case "hs256-public-key":
		head["alg"] = "HS256"
	case "none":
		head["alg"] = "none"
	case "key-2":
		head["kid"] = "key-2"
	}
	headJSON, _ := json.Marshal(head)
	claimsJSON, _ := json.Marshal(claims)
	input := b64(headJSON) + "." + b64(claimsJSON)
	digest := sha256.Sum256([]byte(input))
	var signature []byte
	var err error
	switch how {
	case "none":
		signature = nil
	case "es256":
		r, s, e := ecdsa.Sign(rand.Reader, l.ec1, digest[:])
		err = e
		signature = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case "hs256-public-key":
		mac := hmac.New(sha256.New, publicKeyPEM(&l.rsa1.PublicKey))
		mac.Write([]byte(input))
		signature = mac.Sum(nil)
	case "other-key":
		signature, err = rsa.SignPKCS1v15(rand.Reader, l.rsaOther, crypto.SHA256, digest[:])
	case "key-2":
		signature, err = rsa.SignPKCS1v15(rand.Reader, l.rsa2, crypto.SHA256, digest[:])
	default:
		signature, err = rsa.SignPKCS1v15(rand.Reader, l.rsa1, crypto.SHA256, digest[:])
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(signature)
}

// ------------------------------------------------------------------------------------------------ conformance cases

type casesDocument struct {
	ClientID      string           `json:"clientId"`
	TenantID      string           `json:"tenantId"`
	OtherTenantID string           `json:"otherTenantId"`
	UserID        string           `json:"userId"`
	Header        map[string]any   `json:"header"`
	Claims        map[string]any   `json:"claims"`
	Cases         []map[string]any `json:"cases"`
}

func loadCases(t *testing.T) *casesDocument {
	t.Helper()
	data, err := os.ReadFile("testdata/tokens.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc casesDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return &doc
}

var nowPattern = regexp.MustCompile(`^\$now([+-]\d+)?$`)

// resolve replaces the placeholders of conformance/tokens.json (see its description).
func (l *localLogin) resolve(doc *casesDocument, value any, now int64) any {
	switch v := value.(type) {
	case string:
		if m := nowPattern.FindStringSubmatch(v); m != nil {
			offset := int64(0)
			if m[1] != "" {
				offset, _ = strconv.ParseInt(m[1], 10, 64)
			}
			return now + offset
		}
		s := strings.ReplaceAll(v, "$iss", "$authority/$tenantId/v2.0")
		s = strings.ReplaceAll(s, "$authority", l.origin)
		s = strings.ReplaceAll(s, "$CLIENTID", strings.ToUpper(doc.ClientID))
		s = strings.ReplaceAll(s, "$clientId", doc.ClientID)
		s = strings.ReplaceAll(s, "$TENANTID", strings.ToUpper(doc.TenantID))
		s = strings.ReplaceAll(s, "$otherTenantId", doc.OtherTenantID)
		s = strings.ReplaceAll(s, "$tenantId", doc.TenantID)
		s = strings.ReplaceAll(s, "$userId", doc.UserID)
		return s
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = l.resolve(doc, item, now)
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for k, item := range v {
			out[k] = l.resolve(doc, item, now)
		}
		return out
	}
	return value
}

// buildToken builds the token of one conformance case.
func (l *localLogin) buildToken(t *testing.T, doc *casesDocument, testCase map[string]any, now int64) string {
	t.Helper()
	if raw, ok := testCase["raw"].(string); ok {
		return raw
	}
	header := l.resolve(doc, doc.Header, now).(map[string]any)
	if extra, ok := testCase["header"].(map[string]any); ok {
		for k, v := range l.resolve(doc, extra, now).(map[string]any) {
			header[k] = v
		}
	}
	claims := l.resolve(doc, doc.Claims, now).(map[string]any)
	if changes, ok := testCase["claims"].(map[string]any); ok {
		for k, v := range l.resolve(doc, changes, now).(map[string]any) {
			if v == nil {
				delete(claims, k)
			} else {
				claims[k] = v
			}
		}
	}
	how, _ := testCase["sign"].(string)
	if how == "" {
		how = "key-1"
	}
	token := l.token(t, header, claims, how)
	if tamper, _ := testCase["tamper"].(bool); tamper {
		parts := strings.Split(token, ".")
		changed := map[string]any{}
		for k, v := range claims {
			changed[k] = v
		}
		changed["oid"] = "00000000-aaaa-bbbb-cccc-000000000000"
		data, _ := json.Marshal(changed)
		parts[1] = b64(data)
		token = strings.Join(parts, ".")
	}
	return token
}
