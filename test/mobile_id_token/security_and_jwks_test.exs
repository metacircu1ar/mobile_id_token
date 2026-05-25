defmodule MobileIdToken.SecurityAndJWKSTest do
  use ExUnit.Case, async: false

  alias MobileIdToken.TestSupport.TokenHelpers

  setup do
    TokenHelpers.clear_jwks_cache(:google)

    on_exit(fn ->
      TokenHelpers.clear_jwks_cache(:google)
    end)

    :ok
  end

  test "rejects HS256 algorithm confusion token" do
    client_id = "google-client-hs256"
    kid = "google-hs256-kid"
    claims = google_claims(client_id, sub: "google-hs256-sub")

    {_rs_token, jwk_map} =
      TokenHelpers.build_rs_token_with_alg(%{kid: kid, alg: "RS256", claims: claims})

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    secret =
      jwk_map
      |> Map.take(["kty", "n", "e"])
      |> Jason.encode!()

    token = TokenHelpers.build_hs256_token(%{kid: kid, secret: secret, claims: claims})

    assert {:error, :invalid_signature} =
             MobileIdToken.verify(:google, token, client_ids: [client_id])
  end

  test "rejects alg none token" do
    client_id = "google-client-none"
    kid = "google-none-kid"

    {_token, jwk_map} =
      TokenHelpers.build_rs_token_with_alg(%{kid: kid, claims: google_claims(client_id)})

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    token = TokenHelpers.build_none_token(%{kid: kid, claims: google_claims(client_id)})

    assert {:error, :invalid_signature} =
             MobileIdToken.verify(:google, token, client_ids: [client_id])
  end

  test "rejects RS512 token when only RS256 is allowed" do
    client_id = "google-client-rs512"

    {token, jwk_map} =
      TokenHelpers.build_rs_token_with_alg(%{
        kid: "google-rs512-kid",
        alg: "RS512",
        claims: google_claims(client_id)
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    assert {:error, :invalid_signature} =
             MobileIdToken.verify(:google, token, client_ids: [client_id])
  end

  test "rejects ES256 token when only RS256 is allowed" do
    client_id = "google-client-es256"
    kid = "google-es256-kid"

    {rs256_token, rsa_jwk_map} =
      TokenHelpers.build_rs_token_with_alg(%{
        kid: kid,
        alg: "RS256",
        claims: google_claims(client_id)
      })

    TokenHelpers.put_jwks_cache(:google, [rsa_jwk_map])

    [header_b64, payload_b64, signature_b64] = String.split(rs256_token, ".")

    header =
      header_b64
      |> Base.url_decode64!(padding: false)
      |> Jason.decode!()
      |> Map.put("alg", "ES256")

    token =
      [
        Base.url_encode64(Jason.encode!(header), padding: false),
        payload_b64,
        signature_b64
      ]
      |> Enum.join(".")

    assert {:error, :invalid_signature} =
             MobileIdToken.verify(:google, token, client_ids: [client_id])
  end

  test "fresh cache within ttl does not hit network" do
    client_id = "google-client-cache-hit"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-cache-hit"
      })

    TokenHelpers.put_jwks_cache(:google, [jwk_map])

    TokenHelpers.with_req_stub(
      :google_jwks_should_not_be_called,
      fn conn ->
        send(self(), :jwks_called)
        Req.Test.json(conn, %{"keys" => []})
      end,
      fn ->
        assert {:ok, _claims} = MobileIdToken.verify(:google, token, client_ids: [client_id])
        refute_received :jwks_called
      end
    )
  end

  test "stale cache triggers refresh" do
    client_id = "google-client-stale-refresh"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-stale-refresh"
      })

    stale_at = System.system_time(:second) - 10_000
    TokenHelpers.put_jwks_cache_with_timestamp(:google, [jwk_map], stale_at)

    TokenHelpers.with_req_stub(
      :google_jwks_refresh_called,
      fn conn ->
        send(self(), :jwks_refresh_called)
        Req.Test.json(conn, %{"keys" => [jwk_map]})
      end,
      fn ->
        assert {:ok, _claims} = MobileIdToken.verify(:google, token, client_ids: [client_id])
        assert_received :jwks_refresh_called
      end
    )
  end

  test "stale cache plus refresh failure returns jwks_unavailable" do
    client_id = "google-client-stale-failure"

    {token, jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-stale-failure"
      })

    stale_at = System.system_time(:second) - 10_000
    TokenHelpers.put_jwks_cache_with_timestamp(:google, [jwk_map], stale_at)

    TokenHelpers.with_transport_error(:google_jwks_refresh_down, :econnrefused, fn ->
      assert {:error, :jwks_unavailable} =
               MobileIdToken.verify(:google, token, client_ids: [client_id])
    end)
  end

  test "kid miss in cache succeeds after refresh when key rotated" do
    client_id = "google-client-rotation"

    old_jwk_map = TokenHelpers.build_jwk_map("old-kid")

    {token, new_jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-rotation",
        kid: "new-kid"
      })

    TokenHelpers.put_jwks_cache(:google, [old_jwk_map])

    TokenHelpers.with_req_stub(
      :google_jwks_rotation,
      fn conn ->
        Req.Test.json(conn, %{"keys" => [old_jwk_map, new_jwk_map]})
      end,
      fn ->
        assert {:ok, _claims} = MobileIdToken.verify(:google, token, client_ids: [client_id])
      end
    )
  end

  test "kid miss after refresh still missing returns jwk_not_found" do
    client_id = "google-client-no-rotation"

    old_jwk_map = TokenHelpers.build_jwk_map("old-kid")

    {token, _new_jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-no-rotation",
        kid: "new-kid"
      })

    TokenHelpers.put_jwks_cache(:google, [old_jwk_map])

    TokenHelpers.with_req_stub(
      :google_jwks_no_rotation,
      fn conn ->
        Req.Test.json(conn, %{"keys" => [old_jwk_map]})
      end,
      fn ->
        assert {:error, :jwk_not_found} =
                 MobileIdToken.verify(:google, token, client_ids: [client_id])
      end
    )
  end

  test "jwks response 200 keys null returns jwks_unavailable" do
    client_id = "google-client-keys-null"

    {token, _jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-keys-null"
      })

    TokenHelpers.clear_jwks_cache(:google)

    TokenHelpers.with_req_stub(
      :google_jwks_null,
      fn conn ->
        Req.Test.json(conn, %{"keys" => nil})
      end,
      fn ->
        assert {:error, :jwks_unavailable} =
                 MobileIdToken.verify(:google, token, client_ids: [client_id])
      end
    )
  end

  test "jwks response 200 empty keys returns jwk_not_found" do
    client_id = "google-client-empty-keys"

    {token, _jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-empty-keys",
        kid: "kid-empty"
      })

    TokenHelpers.clear_jwks_cache(:google)

    TokenHelpers.with_req_stub(
      :google_jwks_empty,
      fn conn ->
        Req.Test.json(conn, %{"keys" => []})
      end,
      fn ->
        assert {:error, :jwk_not_found} =
                 MobileIdToken.verify(:google, token, client_ids: [client_id])
      end
    )
  end

  test "jwks response 404 returns jwks_unavailable" do
    client_id = "google-client-404"

    {token, _jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-404"
      })

    TokenHelpers.clear_jwks_cache(:google)

    TokenHelpers.with_req_stub(
      :google_jwks_404,
      fn conn ->
        conn
        |> Plug.Conn.put_status(404)
        |> Req.Test.json(%{"error" => "not found"})
      end,
      fn ->
        assert {:error, :jwks_unavailable} =
                 MobileIdToken.verify(:google, token, client_ids: [client_id])
      end
    )
  end

  test "malformed cached jwk does not crash" do
    client_id = "google-client-malformed-jwk"

    malformed = %{"kid" => "bad-kid", "kty" => "RSA"}

    claims = google_claims(client_id, sub: "google-malformed-jwk")
    token = TokenHelpers.build_none_token(%{kid: "bad-kid", claims: claims})

    TokenHelpers.put_jwks_cache(:google, [malformed])

    assert {:error, :invalid_signature} =
             MobileIdToken.verify(:google, token, client_ids: [client_id])
  end

  defp google_claims(client_id, overrides \\ []) do
    now = DateTime.utc_now() |> DateTime.to_unix()

    base = %{
      "iss" => "https://accounts.google.com",
      "aud" => client_id,
      "exp" => now + 3600,
      "sub" => "google-default-sub",
      "email" => "user@example.com",
      "email_verified" => true
    }

    Enum.into(overrides, base)
  end
end
