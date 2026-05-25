defmodule MobileIdToken.IntegrationTest do
  use ExUnit.Case, async: false

  @moduletag :integration
  @moduletag timeout: :timer.seconds(30)

  test "fetches Apple JWKS from real endpoint" do
    cache_key = {:mobile_id_token, :integration, :apple, make_ref()}

    on_exit(fn ->
      :persistent_term.erase(cache_key)
    end)

    # Uses internal JWKS module to exercise the real network fetch path
    # without requiring a provider-issued token fixture.
    assert {:ok, keys} =
             MobileIdToken.JWKS.fetch(
               "https://appleid.apple.com/auth/keys",
               cache_key,
               600,
               provider: "Apple"
             )

    assert is_list(keys)
    assert keys != []
    assert Enum.any?(keys, &(is_map(&1) and is_binary(&1["kid"])))
    assert Enum.any?(keys, &(is_map(&1) and &1["kty"] == "RSA"))
  end

  test "fetches Google JWKS from real endpoint" do
    cache_key = {:mobile_id_token, :integration, :google, make_ref()}

    on_exit(fn ->
      :persistent_term.erase(cache_key)
    end)

    assert {:ok, keys} =
             MobileIdToken.JWKS.fetch(
               "https://www.googleapis.com/oauth2/v3/certs",
               cache_key,
               600,
               provider: "Google"
             )

    assert is_list(keys)
    assert keys != []
    assert Enum.any?(keys, &(is_map(&1) and is_binary(&1["kid"])))
    assert Enum.any?(keys, &(is_map(&1) and &1["kty"] == "RSA"))
  end
end
