defmodule MobileIdToken.GoogleTest do
  use ExUnit.Case, async: false

  alias MobileIdToken.TestSupport.TokenHelpers

  setup do
    TokenHelpers.clear_jwks_cache(:google)

    on_exit(fn ->
      TokenHelpers.clear_jwks_cache(:google)
    end)

    :ok
  end

  test "verify/3 accepts valid Google token" do
    client_id = "google-client-valid"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-valid"
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:ok, claims} = MobileIdToken.verify(:google, token, client_ids: [client_id])
    assert claims["aud"] == client_id
    assert claims["iss"] == "https://accounts.google.com"
  end

  test "verify/3 returns missing_kid when JWT header has no kid" do
    client_id = "google-client-missing-kid"

    {token, _jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-missing-kid",
        include_kid: false
      })

    assert {:error, :missing_kid} = MobileIdToken.verify(:google, token, client_ids: [client_id])
  end

  test "verify/3 rejects token signed with a different RSA key" do
    client_id = "google-client-invalid-signature"
    kid = "google-kid-invalid-signature"

    {token, _jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-invalid-signature",
        kid: kid
      })

    wrong_jwk_map = TokenHelpers.build_jwk_map(kid)
    TokenHelpers.put_jwks_cache(:google, [wrong_jwk_map])

    assert {:error, :invalid_signature} =
             MobileIdToken.verify(:google, token, client_ids: [client_id])
  end

  test "verify/3 rejects invalid audience" do
    configured_client_id = "google-client-good"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: "google-client-bad",
        email: "user@example.com",
        sub: "google-sub-bad-audience"
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:error, :invalid_audience} =
             MobileIdToken.verify(:google, token, client_ids: [configured_client_id])
  end

  test "verify/3 rejects expired token" do
    client_id = "google-client-expired"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-expired",
        exp: DateTime.utc_now() |> DateTime.add(-60, :second) |> DateTime.to_unix()
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:error, :token_expired} =
             MobileIdToken.verify(:google, token, client_ids: [client_id])
  end

  test "verify/3 rejects unverified email" do
    client_id = "google-client-email-unverified"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        email_verified: false,
        sub: "google-sub-unverified"
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:error, :email_not_verified} =
             MobileIdToken.verify(:google, token, client_ids: [client_id])
  end

  test "verify/3 rejects nonce mismatch" do
    client_id = "google-client-nonce-mismatch"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-nonce-mismatch",
        nonce: "expected-google-nonce"
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:error, :invalid_nonce} =
             MobileIdToken.verify(:google, token,
               client_ids: [client_id],
               nonce: "different-google-nonce"
             )
  end

  test "verify/3 accepts SHA256 hashed nonce claim" do
    client_id = "google-client-nonce-sha"
    nonce = "google-plain-nonce"

    hashed_nonce =
      :crypto.hash(:sha256, nonce)
      |> Base.encode16(case: :lower)

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-nonce-sha",
        nonce: hashed_nonce
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:ok, _claims} =
             MobileIdToken.verify(:google, token,
               client_ids: [client_id],
               nonce: nonce
             )
  end

  test "verify/3 allows missing nonce when token has no nonce claim" do
    client_id = "google-client-missing-nonce"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-missing-nonce",
        nonce: nil
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:ok, _claims} = MobileIdToken.verify(:google, token, client_ids: [client_id])
  end

  test "verify/3 returns jwks_unavailable when JWKS endpoint is down" do
    client_id = "google-client-jwks-down"

    {token, _jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-jwks-down"
      })

    TokenHelpers.clear_jwks_cache(:google)

    TokenHelpers.with_transport_error(:google_jwks_down, :econnrefused, fn ->
      assert {:error, :jwks_unavailable} =
               MobileIdToken.verify(:google, token, client_ids: [client_id])
    end)
  end

  test "verify/3 returns missing_client_id when no audience config is provided" do
    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: "google-client-missing-config",
        email: "user@example.com",
        sub: "google-sub-missing-config"
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:error, :missing_client_id} = MobileIdToken.verify(:google, token, client_ids: [])
  end

  test "verify/3 ignores GOOGLE_OAUTH_CLIENT_IDS env vars" do
    previous_ids = System.get_env("GOOGLE_OAUTH_CLIENT_IDS")
    previous_id = System.get_env("GOOGLE_OAUTH_CLIENT_ID")

    System.put_env("GOOGLE_OAUTH_CLIENT_IDS", "google-client-env-only")
    System.put_env("GOOGLE_OAUTH_CLIENT_ID", "google-client-env-only")

    on_exit(fn ->
      if is_nil(previous_ids),
        do: System.delete_env("GOOGLE_OAUTH_CLIENT_IDS"),
        else: System.put_env("GOOGLE_OAUTH_CLIENT_IDS", previous_ids)

      if is_nil(previous_id),
        do: System.delete_env("GOOGLE_OAUTH_CLIENT_ID"),
        else: System.put_env("GOOGLE_OAUTH_CLIENT_ID", previous_id)
    end)

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: "google-client-env-only",
        email: "user@example.com",
        sub: "google-sub-env-ignored"
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:error, :missing_client_id} = MobileIdToken.verify(:google, token, client_ids: [])
  end
end
