# Changelog

## 0.1.0 (unreleased)

- `Verifier`: checks Rante app access tokens as described in docs/tokens.md of rante-apps-sdk (signature from Rante
  Login's JWKS with key rotation and a refetch cooldown, `aud`, per-tenant `iss`, `exp` / `nbf` / `iat` with clock
  skew, `oid`, `idtyp`, no repeated claims), with optional tenant and scope requirements. Safe for concurrent use.
- `Principal`, `*Error` (with `Status()` and `WWWAuthenticate()`), `BearerToken`, `Middleware`,
  `PrincipalFromContext`, `WriteError`, `FrameAncestors`.
- Passes the shared conformance cases (conformance/tokens.json). On go-jose v4.
- Example external app on net/http.
