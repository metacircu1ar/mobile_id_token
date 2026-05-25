# MobileIdToken

<p align="left">
  <img src="https://raw.githubusercontent.com/metacircu1ar/mobile_id_token/main/logo.png" alt="MobileIdToken logo" width="180">
</p>

`MobileIdToken` verifies Apple and Google OAuth `id_token` JWTs in mobile-first backend flows.

It validates JWT signature (`RS256`), issuer, audience, expiry, subject, nonce, and provider email-verification claims, with in-memory JWKS caching for key rotation.

## Usage

Use `MobileIdToken.verify/3` as the primary API.

### Google example

```elixir
case MobileIdToken.verify(:google, id_token,
       client_ids: ["your-google-client-id"],
       nonce: "optional-nonce"
     ) do
  {:ok, claims} ->
    claims

  {:error, reason} ->
    {:error, reason}
end
```

### Apple example

```elixir
case MobileIdToken.verify(:apple, id_token,
       client_ids: ["com.example.ios"],
       nonce: "expected-nonce"
     ) do
  {:ok, claims} ->
    claims

  {:error, reason} ->
    {:error, reason}
end
```

### Real controller-style example

```elixir
def apple(conn, %{"id_token" => id_token, "nonce" => nonce}) do
  case MobileIdToken.verify(:apple, id_token,
         client_ids: Application.get_env(:my_app, :apple_oauth_client_ids, []),
         nonce: nonce
       ) do
    {:ok, claims} ->
      json(conn, %{data: claims})

    {:error, :invalid_signature} ->
      send_resp(conn, 401, "Invalid token signature")

    {:error, :invalid_audience} ->
      send_resp(conn, 401, "Invalid client id")

    {:error, :token_expired} ->
      send_resp(conn, 401, "Token expired")

    {:error, :invalid_nonce} ->
      send_resp(conn, 401, "Invalid login nonce")

    {:error, :jwks_unavailable} ->
      send_resp(conn, 503, "Unable to verify token right now")

    {:error, reason} ->
      send_resp(conn, 422, Atom.to_string(reason))
  end
end
```

## Why This Exists

Most Elixir OAuth libraries focus on server-side OAuth flows where your backend performs redirect/callback handling.

- `ueberauth_*` providers are great, but coupled to Ueberauth flow abstractions.
- Multi-provider frameworks (for example, broader OAuth/OIDC stacks) can be heavier than needed for mobile apps.

This package focuses on one problem:

- mobile client already completed provider auth
- backend only needs to verify the `id_token` safely

## What It Does

- Fetches and caches provider JWKS (Apple/Google).
- Verifies `RS256` signatures against `kid` selected JWK.
- Validates required claims (`iss`, `aud`, `exp`, `sub`).
- Validates provider email-verification claims.
- Validates nonce (with Apple hash-compatible behavior).
- Returns clear error atoms for HTTP mapping.

## What It Does Not Do

- No redirect/callback OAuth flow orchestration.
- No provider SDK wrapper.
- No user creation/session issuance.
- No persistence layer.
- No Google `hd` (hosted domain) policy enforcement; enforce domain/org rules in host app.

This is a verification primitive you compose inside your own auth pipeline.

## Installation

```elixir
def deps do
  [
    {:mobile_id_token, "~> 0.1.0"}
  ]
end
```

## API

- `MobileIdToken.verify/3`
- `MobileIdToken.Apple.verify_id_token/2`
- `MobileIdToken.Google.verify_id_token/2`

Return shape:

- `{:ok, claims_map}`
- `{:error, reason_atom}`

## Options

- `:client_ids` - accepted `aud` values (`["..."]`, `"a,b"`, or `"single"`).
- `:nonce` - expected nonce.

Audience validation behavior:

- `aud` string: must be one of the configured `:client_ids`.
- `aud` list: every audience in the token must be trusted (no extra untrusted values).
- If `azp` is present, it must be a trusted client ID and one of the token audiences.

Provider-specific nonce behavior:

- Google: optional (`nil` allowed), but if provided must be a non-empty string.
- Apple: required.

## Client ID Configuration

The library intentionally does **not** read app environment variables directly.

Host apps must resolve config and pass `:client_ids` explicitly.

Example host convention (optional):

```elixir
# config/runtime.exs
config :my_app, :google_oauth_client_ids,
  System.get_env("GOOGLE_OAUTH_CLIENT_IDS", "")
  |> String.split(",", trim: true)
  |> Enum.reject(&(&1 == ""))

config :my_app, :apple_oauth_client_ids,
  System.get_env("APPLE_OAUTH_CLIENT_IDS", "")
  |> String.split(",", trim: true)
  |> Enum.reject(&(&1 == ""))
```

Then pass them into `verify/3` as shown in the controller example.

## Nonce Matching Details

Nonce matching accepts either:

- exact plaintext nonce match
- lowercase SHA-256 hash of the expected nonce

This supports providers/SDKs that send hashed nonce claims (commonly seen in Apple flows).

## JWKS Caching

JWKS are cached in `:persistent_term` for 600 seconds.

Verification flow:

1. read cached JWKS
2. select JWK by `kid`
3. if missing, force refresh once and retry
4. fail with `:jwk_not_found` or `:jwks_unavailable`

Current behavior note:

- stale cache + failed refresh returns `:jwks_unavailable` (library does not serve stale keys during refresh failures)

## Error Atoms

- `:invalid_token` (malformed token / unsupported token input shape)
- `:missing_kid`
- `:jwk_not_found`
- `:invalid_signature`
- `:invalid_issuer`
- `:missing_client_id`
- `:invalid_audience`
- `:token_expired`
- `:invalid_claims`
- `:email_not_verified`
- `:invalid_nonce`
- `:jwks_unavailable`
- `:unsupported_provider` (only from `MobileIdToken.verify/3`)

## Provider Notes

Google:

- accepted issuers: `https://accounts.google.com`, `accounts.google.com`
- requires non-empty `email` with truthy `email_verified`

Apple:

- issuer must be `https://appleid.apple.com`
- if email claim exists, `email_verified` must be truthy
- nonce is required by this package API

## Multi-Audience Tokens

If a token's `aud` claim is an array, **every** value must be in `:client_ids`. This matches the OIDC Core §3.1.3.7 requirement to reject tokens that list audiences the client does not trust — not just tokens that omit the client's own ID.

When the `azp` (authorized party) claim is present, it must also be in `:client_ids` **and** appear in the `aud` array.

In typical mobile sign-in flows `aud` is a single string (the app's bundle ID or OAuth client ID), so this rarely matters in practice. The strict behavior is a defense-in-depth measure against cross-application token replay in less common multi-audience flows.

## Security Notes

- Always verify tokens server-side, never trust raw claims from the client.
- Keep `client_ids` scoped to your real app bundle/web client IDs.
- Treat `:jwks_unavailable` as temporary infrastructure failure (typically HTTP 503).
- Keep library versions current to pick up crypto/runtime fixes.
