defmodule MobileIdToken.InputShapeTest do
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

  test "empty token returns invalid_token for both providers" do
    assert {:error, :invalid_token} = verify(:google, "")
    assert {:error, :invalid_token} = verify(:apple, "")
  end

  test "garbage token returns invalid_token for both providers" do
    assert {:error, :invalid_token} = verify(:google, "not-a-jwt")
    assert {:error, :invalid_token} = verify(:apple, "not-a-jwt")
  end

  test "wrong segment count tokens return invalid_token" do
    for token <- ["one", "a.b", "a.b.c.d"] do
      assert {:error, :invalid_token} = verify(:google, token)
      assert {:error, :invalid_token} = verify(:apple, token)
    end
  end

  test "invalid base64 in header returns invalid_token" do
    token = TokenHelpers.build_token_with_segments(["%%%", "e30", "sig"])

    assert {:error, :invalid_token} = verify(:google, token)
    assert {:error, :invalid_token} = verify(:apple, token)
  end

  test "invalid base64 in payload returns invalid_token" do
    header = TokenHelpers.base64url_json(%{"alg" => "RS256", "kid" => "kid1"})
    token = TokenHelpers.build_token_with_segments([header, "%%%", "sig"])

    assert {:error, :invalid_token} = verify(:google, token)
    assert {:error, :invalid_token} = verify(:apple, token)
  end

  test "header that is not JSON returns invalid_token" do
    header = Base.url_encode64("not-json", padding: false)
    payload = Base.url_encode64("{}", padding: false)
    token = TokenHelpers.build_token_with_segments([header, payload, "sig"])

    assert {:error, :invalid_token} = verify(:google, token)
    assert {:error, :invalid_token} = verify(:apple, token)
  end

  test "payload that is not JSON returns invalid_token" do
    header = TokenHelpers.base64url_json(%{"alg" => "RS256", "kid" => "kid1"})
    payload = Base.url_encode64("not-json", padding: false)
    token = TokenHelpers.build_token_with_segments([header, payload, "sig"])

    assert {:error, :invalid_token} = verify(:google, token)
    assert {:error, :invalid_token} = verify(:apple, token)
  end

  test "non-binary token returns invalid_token for provider modules" do
    assert {:error, :invalid_token} = MobileIdToken.Google.verify_id_token(nil, client_ids: ["x"])

    assert {:error, :invalid_token} =
             MobileIdToken.Apple.verify_id_token(123, client_ids: ["x"], nonce: "n")
  end

  test "facade returns invalid_token for known providers with invalid token types" do
    assert {:error, :invalid_token} = MobileIdToken.verify(:google, nil, client_ids: ["x"])
    assert {:error, :invalid_token} = MobileIdToken.verify(:apple, 12345, client_ids: ["x"])
  end

  test "empty kid is treated as missing_kid" do
    client_id = "google-client-empty-kid"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-empty-kid",
        kid: ""
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:error, :missing_kid} = verify(:google, token, client_ids: [client_id])
  end

  test "non-binary kid is treated as missing_kid" do
    client_id = "google-client-int-kid"

    {token, _jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-int-kid",
        kid: 123
      })

    assert {:error, :missing_kid} = verify(:google, token, client_ids: [client_id])
  end

  test "unsupported provider returns unsupported_provider" do
    assert {:error, :unsupported_provider} =
             MobileIdToken.verify(:facebook, "token", client_ids: ["x"])

    assert {:error, :unsupported_provider} =
             MobileIdToken.verify("apple", "token", client_ids: ["x"])
  end

  defp verify(provider, token, opts \\ [])

  defp verify(:google, token, opts),
    do:
      MobileIdToken.verify(
        :google,
        token,
        Keyword.merge([client_ids: ["google-client-default"]], opts)
      )

  defp verify(:apple, token, opts),
    do:
      MobileIdToken.verify(
        :apple,
        token,
        Keyword.merge(
          [client_ids: ["com.example.apple.default"], nonce: "apple-default-nonce"],
          opts
        )
      )
end
