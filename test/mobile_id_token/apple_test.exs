defmodule MobileIdToken.AppleTest do
  use ExUnit.Case, async: false

  alias MobileIdToken.TestSupport.TokenHelpers

  setup do
    TokenHelpers.clear_jwks_cache(:apple)

    on_exit(fn ->
      TokenHelpers.clear_jwks_cache(:apple)
    end)

    :ok
  end

  test "verify/3 accepts valid Apple token" do
    client_id = "com.example.apple.valid"
    nonce = "apple-valid-nonce"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://appleid.apple.com",
        aud: client_id,
        email: "user@example.com",
        sub: "apple-sub-valid",
        nonce: nonce
      })

    TokenHelpers.put_jwks_cache(:apple, [jwk_map])

    assert {:ok, claims} =
             MobileIdToken.verify(:apple, token, client_ids: [client_id], nonce: nonce)

    assert claims["aud"] == client_id
    assert claims["iss"] == "https://appleid.apple.com"
  end

  test "verify/3 returns missing_kid when JWT header has no kid" do
    client_id = "com.example.apple.missing.kid"

    {token, _jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://appleid.apple.com",
        aud: client_id,
        email: "user@example.com",
        sub: "apple-sub-missing-kid",
        include_kid: false
      })

    assert {:error, :missing_kid} =
             MobileIdToken.verify(:apple, token, client_ids: [client_id], nonce: "expected")
  end

  test "verify/3 rejects invalid signature" do
    client_id = "com.example.apple.invalid.signature"
    kid = "apple-kid-invalid-signature"

    {token, _jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://appleid.apple.com",
        aud: client_id,
        email: "user@example.com",
        sub: "apple-sub-invalid-signature",
        kid: kid,
        nonce: "expected-apple-nonce"
      })

    wrong_jwk_map = TokenHelpers.build_jwk_map(kid)
    TokenHelpers.put_jwks_cache(:apple, [wrong_jwk_map])

    assert {:error, :invalid_signature} =
             MobileIdToken.verify(:apple, token,
               client_ids: [client_id],
               nonce: "expected-apple-nonce"
             )
  end

  test "verify/3 rejects invalid audience" do
    configured_client_id = "com.example.apple.good"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://appleid.apple.com",
        aud: "com.example.apple.bad",
        email: "user@example.com",
        sub: "apple-sub-bad-audience",
        nonce: "expected-apple-nonce"
      })

    TokenHelpers.put_jwks_cache(:apple, [jwk_map])

    assert {:error, :invalid_audience} =
             MobileIdToken.verify(:apple, token,
               client_ids: [configured_client_id],
               nonce: "expected-apple-nonce"
             )
  end

  test "verify/3 rejects expired token" do
    client_id = "com.example.apple.expired"
    nonce = "apple-expired-nonce"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://appleid.apple.com",
        aud: client_id,
        email: "user@example.com",
        sub: "apple-sub-expired",
        nonce: nonce,
        exp: DateTime.utc_now() |> DateTime.add(-60, :second) |> DateTime.to_unix()
      })

    TokenHelpers.put_jwks_cache(:apple, [jwk_map])

    assert {:error, :token_expired} =
             MobileIdToken.verify(:apple, token, client_ids: [client_id], nonce: nonce)
  end

  test "verify/3 rejects nonce mismatch" do
    client_id = "com.example.apple.nonce.mismatch"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://appleid.apple.com",
        aud: client_id,
        email: "user@example.com",
        sub: "apple-sub-nonce-mismatch",
        nonce: "expected-apple-nonce"
      })

    TokenHelpers.put_jwks_cache(:apple, [jwk_map])

    assert {:error, :invalid_nonce} =
             MobileIdToken.verify(:apple, token,
               client_ids: [client_id],
               nonce: "different-apple-nonce"
             )
  end

  test "verify/3 accepts SHA256 hashed nonce claim" do
    client_id = "com.example.apple.nonce.sha"
    nonce = "my-plain-nonce"

    hashed_nonce =
      :crypto.hash(:sha256, nonce)
      |> Base.encode16(case: :lower)

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://appleid.apple.com",
        aud: client_id,
        email: "user@example.com",
        sub: "apple-sub-nonce-sha",
        nonce: hashed_nonce
      })

    TokenHelpers.put_jwks_cache(:apple, [jwk_map])

    assert {:ok, _claims} =
             MobileIdToken.verify(:apple, token, client_ids: [client_id], nonce: nonce)
  end

  test "verify/3 requires nonce option for Apple" do
    client_id = "com.example.apple.nonce.required"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://appleid.apple.com",
        aud: client_id,
        email: "user@example.com",
        sub: "apple-sub-nonce-required",
        nonce: "expected-apple-nonce"
      })

    TokenHelpers.put_jwks_cache(:apple, [jwk_map])

    assert {:error, :invalid_nonce} = MobileIdToken.verify(:apple, token, client_ids: [client_id])
  end

  test "verify/3 rejects unverified email claim when email is present" do
    client_id = "com.example.apple.email.unverified"
    nonce = "apple-email-unverified-nonce"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://appleid.apple.com",
        aud: client_id,
        email: "user@example.com",
        email_verified: false,
        sub: "apple-sub-email-unverified",
        nonce: nonce
      })

    TokenHelpers.put_jwks_cache(:apple, [jwk_map])

    assert {:error, :email_not_verified} =
             MobileIdToken.verify(:apple, token, client_ids: [client_id], nonce: nonce)
  end

  test "verify/3 allows token without email claim" do
    client_id = "com.example.apple.no.email"
    nonce = "apple-no-email-nonce"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://appleid.apple.com",
        aud: client_id,
        sub: "apple-sub-no-email",
        nonce: nonce,
        email: nil,
        email_verified: nil
      })

    TokenHelpers.put_jwks_cache(:apple, [jwk_map])

    assert {:ok, claims} =
             MobileIdToken.verify(:apple, token, client_ids: [client_id], nonce: nonce)

    refute Map.has_key?(claims, "email")
  end

  test "verify/3 returns jwks_unavailable when JWKS endpoint is down" do
    client_id = "com.example.apple.jwks.down"

    {token, _jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://appleid.apple.com",
        aud: client_id,
        email: "user@example.com",
        sub: "apple-sub-jwks-down",
        nonce: "apple-jwks-down-nonce"
      })

    TokenHelpers.clear_jwks_cache(:apple)

    TokenHelpers.with_transport_error(:apple_jwks_down, :econnrefused, fn ->
      assert {:error, :jwks_unavailable} =
               MobileIdToken.verify(:apple, token,
                 client_ids: [client_id],
                 nonce: "apple-jwks-down-nonce"
               )
    end)
  end

  test "verify/3 returns missing_client_id when no audience config is provided" do
    nonce = "apple-missing-client-id"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://appleid.apple.com",
        aud: "com.example.apple.no-client-id",
        email: "user@example.com",
        sub: "apple-sub-missing-client-id",
        nonce: nonce
      })

    TokenHelpers.put_jwks_cache(:apple, [jwk_map])

    assert {:error, :missing_client_id} =
             MobileIdToken.verify(:apple, token, client_ids: [], nonce: nonce)
  end

  test "verify/3 ignores APPLE_OAUTH_CLIENT_IDS env vars" do
    previous_ids = System.get_env("APPLE_OAUTH_CLIENT_IDS")
    previous_id = System.get_env("APPLE_OAUTH_CLIENT_ID")

    System.put_env("APPLE_OAUTH_CLIENT_IDS", "com.example.apple.env.only")
    System.put_env("APPLE_OAUTH_CLIENT_ID", "com.example.apple.env.only")

    on_exit(fn ->
      if is_nil(previous_ids),
        do: System.delete_env("APPLE_OAUTH_CLIENT_IDS"),
        else: System.put_env("APPLE_OAUTH_CLIENT_IDS", previous_ids)

      if is_nil(previous_id),
        do: System.delete_env("APPLE_OAUTH_CLIENT_ID"),
        else: System.put_env("APPLE_OAUTH_CLIENT_ID", previous_id)
    end)

    nonce = "apple-env-ignored"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://appleid.apple.com",
        aud: "com.example.apple.env.only",
        email: "user@example.com",
        sub: "apple-sub-env-ignored",
        nonce: nonce
      })

    TokenHelpers.put_jwks_cache(:apple, [jwk_map])

    assert {:error, :missing_client_id} =
             MobileIdToken.verify(:apple, token, client_ids: [], nonce: nonce)
  end
end
