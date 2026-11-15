// An external Rante app on net/http: the page gets an access token from Rante and calls /api/me, which checks it with
// the Rante Apps server SDK.
//
//	RANTE_CLIENT_ID=<your app's client ID> go run ./examples/nethttp
package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"

	ranteapps "github.com/rante-corporation/rante-apps-sdk-go"
)

//go:embed public
var public embed.FS

func main() {
	clientID := os.Getenv("RANTE_CLIENT_ID")
	if clientID == "" {
		log.Fatal("Set RANTE_CLIENT_ID to your app's Application (client) ID.")
	}
	var tenants []string
	if value := os.Getenv("RANTE_TENANTS"); value != "" {
		for _, t := range strings.Split(value, ",") {
			tenants = append(tenants, strings.TrimSpace(t))
		}
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	// One verifier for the whole process: it caches Rante Login's signing keys and is safe for concurrent use.
	verifier, err := ranteapps.NewVerifier(ranteapps.Config{ClientID: clientID, Tenants: tenants})
	if err != nil {
		log.Fatal(err)
	}
	page, err := public.ReadFile("public/index.html")
	if err != nil {
		log.Fatal(err)
	}
	index := strings.Replace(string(page), "__RANTE_CLIENT_ID__", verifier.ClientID(), 1)
	static, err := fs.Sub(public, "public")
	if err != nil {
		log.Fatal(err)
	}
	files := http.FileServer(http.FS(static))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		// Only Rante may frame the app; everything else loads from this server.
		w.Header().Set("Content-Security-Policy", ranteapps.FrameAncestors+"; default-src 'self'; object-src 'none'; base-uri 'none'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(index))
	})
	for _, name := range []string{"/app.js", "/style.css", "/rante-sdk.js"} {
		mux.Handle("GET "+name, files)
	}
	mux.Handle("GET /api/me", verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := ranteapps.PrincipalFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"userId":    p.UserID,
			"tenantId":  p.TenantID,
			"name":      p.Name,
			"username":  p.Username,
			"scopes":    p.Scopes,
			"expiresAt": p.ExpiresAt,
		})
	})))

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		mux.ServeHTTP(w, r)
	})
	log.Printf("External app example on http://localhost:%s", port)
	log.Print("Rante opens external apps from an https address: put this server behind one and register it in manifest.json.")
	log.Fatal(http.ListenAndServe("127.0.0.1:"+port, handler))
}
