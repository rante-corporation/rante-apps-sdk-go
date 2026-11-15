# Rante Apps server SDK for Go

Check, on your server, the access tokens your Rante app's frontend gets from
[`Rante.getAccessToken()`](https://github.com/rante-corporation/rante-apps-sdk/tree/main/packages/sdk), and find out
who and which tenant each request is for. Built on [go-jose](https://github.com/go-jose/go-jose). Go 1.26 or later.

What a token contains and what is checked: [docs/tokens.md](https://github.com/rante-corporation/rante-apps-sdk/blob/main/docs/tokens.md).
The same checks, error codes and test cases exist for [Node.js](https://github.com/rante-corporation/rante-apps-sdk-node),
[Python](https://github.com/rante-corporation/rante-apps-sdk-python), [.NET](https://github.com/rante-corporation/rante-apps-sdk-dotnet),
[Java](https://github.com/rante-corporation/rante-apps-sdk-java) and [PHP](https://github.com/rante-corporation/rante-apps-sdk-php).

Status: 0.1.0. Rante's hosting of apps is being built to this design; tokens are issued once it is live.

## Install

```bash
go get github.com/rante-corporation/rante-apps-sdk-go@main
```

## Use

```go
import ranteapps "github.com/rante-corporation/rante-apps-sdk-go"

// One verifier per app, created once: it caches Rante Login's signing keys and is safe for concurrent use.
verifier, err := ranteapps.NewVerifier(ranteapps.Config{ClientID: os.Getenv("RANTE_CLIENT_ID")})
if err != nil {
	log.Fatal(err)
}

http.Handle("GET /api/me", verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	p, _ := ranteapps.PrincipalFromContext(r.Context())
	fmt.Fprintf(w, "%s in %s, scopes %v", p.UserID, p.TenantID, p.Scopes)
})))
```

`Middleware` answers a missing or refused token with the error's status (401, 403 or 503), a JSON body
`{"error":"<code>","message":"..."}` and a `WWW-Authenticate` header. Without it:

```go
p, err := verifier.Verify(ctx, ranteapps.BearerToken(r.Header.Get("Authorization")))
if err != nil {
	ranteapps.WriteError(w, err) // or inspect err.(*ranteapps.Error): Code, Status(), WWWAuthenticate()
	return
}
```

Your pages should send `Content-Security-Policy: frame-ancestors https://portal.rante.com`
(`ranteapps.FrameAncestors`) so that only Rante can frame them.

## Config

| Field | Default (zero value) | |
|---|---|---|
| `ClientID` | (required) | Your app's Application (client) ID. |
| `Tenants` | any tenant | Accept tokens of these tenants only (`tenant_not_allowed` otherwise). |
| `RequiredScopes` | none | Scopes every token must have (`insufficient_scope` otherwise). |
| `ExtraAudiences` | none | Audiences accepted besides the client ID, such as `api://{clientId}`. |
| `Authority` | `https://login.rante.com` | http is accepted for localhost only, for tests. |
| `ClockSkew` | 60 s (negative: none) | Clock difference tolerated for `exp`, `nbf` and `iat`. |
| `Algorithms` | `RS256` | `RS256` and `ES256` are supported. |
| `Timeout` | 5 s | For each request to Rante Login. |
| `JWKSCooldown` | 30 s (negative: none) | Minimum time between two key fetches (an unknown `kid` triggers one). |
| `JWKSMaxAge` | 10 min | How long fetched keys are used before they are fetched again. |
| `HTTPClient` | a client of its own | For proxies or tests. |

## The principal

`*Principal`: `UserID` (oid), `TenantID` (tid), `Subject` (sub: stable, different for every app), `Name`, `Username`
(preferred_username), `Email`, `AppID` (your client ID), `AuthorizedParty` (azp), `Scopes` (from scp), `Roles`,
`IssuedAt` (zero without iat), `ExpiresAt`, `Issuer` and `Claims` (every claim; numbers are `json.Number`).

## Errors

Errors are `*ranteapps.Error` with `Code` one of `missing_token`, `invalid_token`, `token_expired` (401),
`tenant_not_allowed`, `insufficient_scope` (403), `discovery_failed`, `network_error` (503) or
`invalid_configuration` (500). `Status()` is that HTTP status and `WWWAuthenticate()` the header value to send with
it (or `""`).

## Example

[examples/nethttp](examples/nethttp) is a complete external app on net/http: a page that asks Rante for a token and
an `/api/me` endpoint that checks it.

```bash
RANTE_CLIENT_ID=<your-app-id> go run ./examples/nethttp
```

Rante opens external apps from an `https://` address, so register the server behind one in
[manifest.json](examples/nethttp/manifest.json).

## Tests

```bash
go vet ./...
go test ./...
```

`testdata/tokens.json` is a copy of
[conformance/tokens.json](https://github.com/rante-corporation/rante-apps-sdk/blob/main/conformance/tokens.json): the
cases every server SDK passes. The tests sign them with keys generated for the run and serve those keys from a local
stand-in for Rante Login; nothing leaves the machine.

## License

[MIT](LICENSE). Report security problems privately through this repository's Security tab.
