defmodule MobileIdToken.JWKSResponseShapesTest do
  use ExUnit.Case, async: false

  alias MobileIdToken.TestSupport.TokenHelpers

  setup do
    TokenHelpers.clear_jwks_cache(:google)

    on_exit(fn ->
      TokenHelpers.clear_jwks_cache(:google)
    end)

    :ok
  end

  test "jwks response 200 without keys field returns jwks_unavailable" do
    client_id = "google-client-keys-missing"

    {token, _jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-keys-missing"
      })

    TokenHelpers.with_req_stub(
      {:google_jwks_keys_missing, make_ref()},
      fn conn ->
        Req.Test.json(conn, %{"not_keys" => []})
      end,
      fn ->
        assert {:error, :jwks_unavailable} =
                 MobileIdToken.verify(:google, token, client_ids: [client_id])
      end
    )
  end

  test "jwks response 200 with non-list keys returns jwks_unavailable" do
    client_id = "google-client-keys-not-list"

    {token, _jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-keys-not-list"
      })

    TokenHelpers.with_req_stub(
      {:google_jwks_keys_not_list, make_ref()},
      fn conn ->
        Req.Test.json(conn, %{"keys" => "not-a-list"})
      end,
      fn ->
        assert {:error, :jwks_unavailable} =
                 MobileIdToken.verify(:google, token, client_ids: [client_id])
      end
    )
  end

  test "jwks response 200 with non-map body returns jwks_unavailable" do
    client_id = "google-client-body-not-map"

    {token, _jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-body-not-map"
      })

    TokenHelpers.with_req_stub(
      {:google_jwks_body_not_map, make_ref()},
      fn conn ->
        Req.Test.text(conn, "not-a-json-object")
      end,
      fn ->
        assert {:error, :jwks_unavailable} =
                 MobileIdToken.verify(:google, token, client_ids: [client_id])
      end
    )
  end

  test "jwks response 500 returns jwks_unavailable" do
    client_id = "google-client-500"

    {token, _jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-500"
      })

    TokenHelpers.with_req_stub(
      {:google_jwks_500, make_ref()},
      fn conn ->
        conn
        |> Plug.Conn.put_status(500)
        |> Req.Test.json(%{"error" => "internal"})
      end,
      fn ->
        assert {:error, :jwks_unavailable} =
                 MobileIdToken.verify(:google, token, client_ids: [client_id])
      end
    )
  end

  test "jwks response 503 returns jwks_unavailable" do
    client_id = "google-client-503"

    {token, _jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-503"
      })

    TokenHelpers.with_req_stub(
      {:google_jwks_503, make_ref()},
      fn conn ->
        conn
        |> Plug.Conn.put_status(503)
        |> Req.Test.json(%{"error" => "unavailable"})
      end,
      fn ->
        assert {:error, :jwks_unavailable} =
                 MobileIdToken.verify(:google, token, client_ids: [client_id])
      end
    )
  end

  test "jwks timeout returns jwks_unavailable" do
    client_id = "google-client-timeout"

    {token, _jwk_map} =
      TokenHelpers.build_id_token(%{
        iss: "https://accounts.google.com",
        aud: client_id,
        email: "user@example.com",
        sub: "google-sub-timeout"
      })

    TokenHelpers.with_transport_error({:google_jwks_timeout, make_ref()}, :timeout, fn ->
      assert {:error, :jwks_unavailable} =
               MobileIdToken.verify(:google, token, client_ids: [client_id])
    end)
  end
end
