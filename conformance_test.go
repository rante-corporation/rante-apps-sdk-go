package ranteapps

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// TestConformance runs testdata/tokens.json (a copy of rante-apps-sdk/conformance/tokens.json): the cases every Rante
// Apps server SDK passes, in every language.
func TestConformance(t *testing.T) {
	login := startLocalLogin(t)
	doc := loadCases(t)
	shared, err := NewVerifier(Config{ClientID: doc.ClientID, Authority: login.origin})
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]func(*Principal) any{
		"userId":          func(p *Principal) any { return p.UserID },
		"tenantId":        func(p *Principal) any { return p.TenantID },
		"subject":         func(p *Principal) any { return p.Subject },
		"name":            func(p *Principal) any { return p.Name },
		"username":        func(p *Principal) any { return p.Username },
		"authorizedParty": func(p *Principal) any { return p.AuthorizedParty },
		"scopes": func(p *Principal) any {
			out := make([]any, len(p.Scopes))
			for i, s := range p.Scopes {
				out[i] = s
			}
			return out
		},
	}
	for _, testCase := range doc.Cases {
		name, _ := testCase["name"].(string)
		t.Run(name, func(t *testing.T) {
			now := time.Now().Unix()
			verifier := shared
			if raw, ok := testCase["options"].(map[string]any); ok {
				options := login.resolve(doc, raw, now).(map[string]any)
				cfg := Config{ClientID: doc.ClientID, Authority: login.origin}
				cfg.Tenants = stringList(options["tenants"])
				cfg.RequiredScopes = stringList(options["requiredScopes"])
				v, err := NewVerifier(cfg)
				if err != nil {
					t.Fatal(err)
				}
				verifier = v
			}
			token := login.buildToken(t, doc, testCase, now)
			principal, err := verifier.Verify(context.Background(), token)
			expect, _ := testCase["expect"].(string)
			if expect == "" {
				if err != nil {
					t.Fatalf("expected a valid token, got %v", err)
				}
				if expected, ok := testCase["principal"].(map[string]any); ok {
					for field, value := range login.resolve(doc, expected, now).(map[string]any) {
						if got := fields[field](principal); !reflect.DeepEqual(got, value) {
							t.Errorf("%s: got %v, want %v", field, got, value)
						}
					}
				}
				return
			}
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("expected %s, got %v", expect, err)
			}
			if e.Code != expect {
				t.Fatalf("expected %s, got %s: %s", expect, e.Code, e.Message)
			}
		})
	}
}

func stringList(value any) []string {
	list, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
