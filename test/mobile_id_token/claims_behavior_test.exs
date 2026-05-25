defmodule MobileIdToken.ClaimsBehaviorTest do
  use ExUnit.Case, async: false

  alias MobileIdToken.TestSupport.TokenHelpers

  setup do
    TokenHelpers.clear_jwks_cache(:google)
    TokenHelpers.clear_jwks_cache(:apple)

    on_exit(fn ->
      TokenHelpers.clear_jwks_cache(:google)
      TokenHelpers.clear_jwks_cache(:apple)
    end)

    :ok
  end

  test "google accepts aud claim list only when all audiences are trusted" do
    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: ["google-aud-1", "google-aud-2"],
        email: "user@example.com",
        sub: "google-aud-list"
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:ok, _claims} =
             MobileIdToken.verify(:google, token, client_ids: ["google-aud-1", "google-aud-2"])
  end

  test "google rejects aud claim list when none match" do
    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: ["google-aud-1", "google-aud-2"],
        email: "user@example.com",
        sub: "google-aud-list-none"
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:error, :invalid_audience} =
             MobileIdToken.verify(:google, token, client_ids: ["google-aud-3"])
  end

  test "google rejects aud claim list when token contains untrusted extra audience" do
    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: ["google-aud-1", "google-untrusted-aud"],
        email: "user@example.com",
        sub: "google-aud-list-untrusted"
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:error, :invalid_audience} =
             MobileIdToken.verify(:google, token, client_ids: ["google-aud-1"])
  end

  test "google accepts multi-audience token when azp is trusted and in aud list" do
    claims = %{
      "iss" => "https://accounts.google.com",
      "aud" => ["google-aud-1", "google-aud-2"],
      "azp" => "google-aud-2",
      "exp" => DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.to_unix(),
      "sub" => "google-aud-azp-valid",
      "email" => "user@example.com",
      "email_verified" => true
    }

    {token, jwk_map} =
      TokenHelpers.build_rs_token_with_alg(%{
        kid: "google-aud-azp-valid-kid",
        claims: claims
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:ok, _claims} =
             MobileIdToken.verify(:google, token, client_ids: ["google-aud-1", "google-aud-2"])
  end

  test "google rejects multi-audience token when azp is untrusted or outside aud list" do
    claims_variants = [
      %{
        "iss" => "https://accounts.google.com",
        "aud" => ["google-aud-1", "google-aud-2"],
        "azp" => "google-untrusted-azp",
        "exp" => DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.to_unix(),
        "sub" => "google-aud-azp-untrusted",
        "email" => "user@example.com",
        "email_verified" => true
      },
      %{
        "iss" => "https://accounts.google.com",
        "aud" => ["google-aud-1", "google-aud-2"],
        "azp" => "google-aud-3",
        "exp" => DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.to_unix(),
        "sub" => "google-aud-azp-not-in-aud",
        "email" => "user@example.com",
        "email_verified" => true
      }
    ]

    Enum.each(claims_variants, fn claims ->
      {token, jwk_map} =
        TokenHelpers.build_rs_token_with_alg(%{
          kid: "google-aud-azp-invalid-kid-#{System.unique_integer([:positive])}",
          claims: claims
        })

      TokenHelpers.put_jwks_cache(:google, [jwk_map])

      assert {:error, :invalid_audience} =
               MobileIdToken.verify(:google, token, client_ids: ["google-aud-1", "google-aud-2"])

      TokenHelpers.clear_jwks_cache(:google)
    end)
  end

  test "google rejects audience of wrong type" do
    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: 123,
        email: "user@example.com",
        sub: "google-aud-number"
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:error, :invalid_audience} =
             MobileIdToken.verify(:google, token, client_ids: ["google-aud-any"])
  end

  test "client_ids supports comma separated string" do
    client_id = "google-client-comma"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-client-comma"
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:ok, _claims} =
             MobileIdToken.verify(:google, token, client_ids: "x, #{client_id}, y")
  end

  test "client_ids supports space separated string" do
    client_id = "google-client-space"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-client-space"
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:ok, _claims} =
             MobileIdToken.verify(:google, token, client_ids: "x #{client_id} y")
  end

  test "client_ids supports list of atoms" do
    client_id = "google-client-atom"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-client-atom"
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:ok, _claims} =
             MobileIdToken.verify(:google, token, client_ids: [:"#{client_id}"])
  end

  test "client_ids nil and non-list values produce missing_client_id" do
    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: "google-client-missing",
        email: "user@example.com",
        sub: "google-client-missing"
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:error, :missing_client_id} = MobileIdToken.verify(:google, token, client_ids: nil)
    assert {:error, :missing_client_id} = MobileIdToken.verify(:google, token, client_ids: 123)
    assert {:error, :missing_client_id} = MobileIdToken.verify(:google, token, client_ids: %{})
  end

  test "invalid exp types return invalid_claims instead of crashing" do
    for exp <- [nil, "12345", 12345.0] do
      {token, jwk_map} =
        TokenHelpers.build_id_token(%{
          iss: "https://accounts.google.com",
          aud: "google-client-exp-invalid",
          email: "user@example.com",
          sub: "google-exp-invalid-#{inspect(exp)}",
          exp: exp
        })

      TokenHelpers.put_jwks_cache(:google, [jwk_map])

      assert {:error, :invalid_claims} =
               MobileIdToken.verify(:google, token, client_ids: ["google-client-exp-invalid"])

      TokenHelpers.clear_jwks_cache(:google)
    end
  end

  test "exp equal current unix second is accepted" do
    client_id = "google-client-exp-now"
    exp_now = DateTime.utc_now() |> DateTime.to_unix()

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-exp-now",
        exp: exp_now
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:ok, _claims} = MobileIdToken.verify(:google, token, client_ids: [client_id])
  end

  test "google with no email claim fails closed" do
    client_id = "google-client-no-email"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        sub: "google-sub-no-email",
        email: nil,
        email_verified: nil
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:error, :email_not_verified} =
             MobileIdToken.verify(:google, token, client_ids: [client_id])
  end

  test "google empty nonce option is rejected" do
    client_id = "google-client-empty-nonce"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-empty-nonce"
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:error, :invalid_nonce} =
             MobileIdToken.verify(:google, token, client_ids: [client_id], nonce: "")
  end

  test "google allows missing nonce even when token has nonce" do
    client_id = "google-client-no-nonce-opt"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-no-nonce-opt",
        nonce: "token-nonce-value"
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:ok, _claims} = MobileIdToken.verify(:google, token, client_ids: [client_id])
  end

  test "apple uppercase hashed nonce claim is accepted" do
    client_id = "com.example.apple.uppercase-hash"
    nonce = "plain-nonce"

    hashed_nonce =
      :crypto.hash(:sha256, nonce)
      |> Base.encode16(case: :upper)

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://appleid.apple.com",
        aud: client_id,
        email: "user@example.com",
        sub: "apple-uppercase-hash",
        nonce: hashed_nonce
      })

    TokenHelpers.put_jwks_cache(:apple, [jwk_map])

    assert {:ok, _claims} =
             MobileIdToken.verify(:apple, token, client_ids: [client_id], nonce: nonce)
  end

  test "apple plain nonce matching is case-sensitive" do
    client_id = "com.example.apple.case-sensitive"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://appleid.apple.com",
        aud: client_id,
        email: "user@example.com",
        sub: "apple-case-sensitive",
        nonce: "ABC"
      })

    TokenHelpers.put_jwks_cache(:apple, [jwk_map])

    assert {:error, :invalid_nonce} =
             MobileIdToken.verify(:apple, token, client_ids: [client_id], nonce: "abc")
  end

  test "apple rejects aud claim list when token contains untrusted extra audience" do
    claims = %{
      "iss" => "https://appleid.apple.com",
      "aud" => ["com.example.apple.aud-1", "com.example.apple.untrusted-aud"],
      "azp" => "com.example.apple.aud-1",
      "exp" => DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.to_unix(),
      "sub" => "apple-aud-list-untrusted",
      "nonce" => "apple-aud-list-untrusted-nonce"
    }

    {token, jwk_map} =
      TokenHelpers.build_rs_token_with_alg(%{
        kid: "apple-aud-list-untrusted-kid",
        claims: claims
      })

    TokenHelpers.put_jwks_cache(:apple, [jwk_map])

    assert {:error, :invalid_audience} =
             MobileIdToken.verify(:apple, token,
               client_ids: ["com.example.apple.aud-1"],
               nonce: "apple-aud-list-untrusted-nonce"
             )
  end

  test "issuer mismatch cases return invalid_issuer" do
    {google_bad_token, google_jwk} =
      TokenHelpers.build_id_token(%{
        iss: "accounts.google.com/",
        aud: "google-client-issuer",
        email: "user@example.com",
        sub: "google-bad-issuer"
      })

    TokenHelpers.put_jwks_cache(:google, [google_jwk])

    assert {:error, :invalid_issuer} =
             MobileIdToken.verify(:google, google_bad_token, client_ids: ["google-client-issuer"])

    {apple_bad_token, apple_jwk} =
      TokenHelpers.build_id_token(%{
        iss: "appleid.apple.com",
        aud: "com.example.apple.issuer",
        email: "user@example.com",
        sub: "apple-bad-issuer",
        nonce: "apple-issuer-nonce"
      })

    TokenHelpers.put_jwks_cache(:apple, [apple_jwk])

    assert {:error, :invalid_issuer} =
             MobileIdToken.verify(:apple, apple_bad_token,
               client_ids: ["com.example.apple.issuer"],
               nonce: "apple-issuer-nonce"
             )
  end

  test "google sub validation rejects empty, whitespace, missing, and non-string values" do
    base_claims = %{
      "iss" => "https://accounts.google.com",
      "aud" => "google-client-sub-validation",
      "exp" => DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.to_unix(),
      "email" => "user@example.com",
      "email_verified" => true
    }

    claims_variants = [
      Map.put(base_claims, "sub", ""),
      Map.put(base_claims, "sub", "   "),
      Map.delete(base_claims, "sub"),
      Map.put(base_claims, "sub", 12345)
    ]

    Enum.each(claims_variants, fn claims ->
      {token, jwk_map} =
        TokenHelpers.build_rs_token_with_alg(%{
          kid: "google-sub-validation-kid-#{System.unique_integer([:positive])}",
          claims: claims
        })

      TokenHelpers.put_jwks_cache(:google, [jwk_map])

      assert {:error, :invalid_claims} =
               MobileIdToken.verify(:google, token, client_ids: ["google-client-sub-validation"])

      TokenHelpers.clear_jwks_cache(:google)
    end)
  end

  test "apple sub validation rejects empty, whitespace, missing, and non-string values" do
    base_claims = %{
      "iss" => "https://appleid.apple.com",
      "aud" => "com.example.apple.sub.validation",
      "exp" => DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.to_unix(),
      "nonce" => "apple-sub-validation-nonce"
    }

    claims_variants = [
      Map.put(base_claims, "sub", ""),
      Map.put(base_claims, "sub", "   "),
      Map.delete(base_claims, "sub"),
      Map.put(base_claims, "sub", 12345)
    ]

    Enum.each(claims_variants, fn claims ->
      {token, jwk_map} =
        TokenHelpers.build_rs_token_with_alg(%{
          kid: "apple-sub-validation-kid-#{System.unique_integer([:positive])}",
          claims: claims
        })

      TokenHelpers.put_jwks_cache(:apple, [jwk_map])

      assert {:error, :invalid_claims} =
               MobileIdToken.verify(:apple, token,
                 client_ids: ["com.example.apple.sub.validation"],
                 nonce: "apple-sub-validation-nonce"
               )

      TokenHelpers.clear_jwks_cache(:apple)
    end)
  end
end
