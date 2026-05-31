# Changelog

All notable changes to `mobile_id_token` will be documented in this file.

The format is based on Keep a Changelog.

## [0.1.1] - 2026-06-01

### Fixed

- Relax `azp` validation so trusted authorized parties no longer have to appear in the token `aud` value.
- Align Google/OIDC audience handling for tokens where `aud` and `azp` are different trusted client IDs.

## [0.1.0] - 2026-05-25

Initial release.

- Apple and Google `id_token` verification via `MobileIdToken.verify/3`
- JWKS fetching with `:persistent_term` caching and key-rotation refresh
- Strict `RS256` signature verification (rejects `HS256` / `none` / `RS512` / `ES256` algorithm confusion)
- OIDC `azp` (authorized party) validation for multi-audience tokens
- Provider-asymmetric email verification (Google requires verified email; Apple optional)
- SHA-256 hash-aware nonce matching for Apple-style hashed nonce claims
- Opt-in real-network integration tests against Apple and Google JWKS endpoints (`MOBILE_ID_TOKEN_INTEGRATION=1`)
