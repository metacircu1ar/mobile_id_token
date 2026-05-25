defmodule MobileIdToken.TestSupport.TokenHelpers do
  @google_cache_key {:mobile_id_token, :google_jwks}
  @apple_cache_key {:mobile_id_token, :apple_jwks}

  def oauth_nonce, do: "mobile-id-token-test-nonce"

  def build_id_token(opts) when is_map(opts) do
    kid = Map.get(opts, :kid, "kid-#{System.unique_integer([:positive])}")
    include_kid? = Map.get(opts, :include_kid, true)

    jwk = JOSE.JWK.generate_key({:rsa, 2048})
    jwk_map = jwk |> JOSE.JWK.to_map() |> elem(1) |> Map.put("kid", kid)

    exp =
      Map.get_lazy(opts, :exp, fn ->
        DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.to_unix()
      end)

    claims =
      %{
        "iss" => Map.fetch!(opts, :iss),
        "aud" => Map.fetch!(opts, :aud),
        "exp" => exp,
        "sub" => Map.fetch!(opts, :sub)
      }
      |> maybe_put_claim("nonce", Map.get(opts, :nonce, oauth_nonce()))
      |> maybe_put_claim("email", Map.get(opts, :email))
      |> maybe_put_claim("name", Map.get(opts, :name, "Test User"))
      |> maybe_put_claim(
        "email_verified",
        Map.get(opts, :email_verified, default_email_verified(opts))
      )

    header =
      %{"alg" => "RS256"}
      |> maybe_put_claim("kid", if(include_kid?, do: kid, else: nil))

    {_, token} =
      JOSE.JWT.sign(jwk, header, claims)
      |> JOSE.JWS.compact()

    {token, jwk_map}
  end

  def build_jwk_map(kid) when is_binary(kid) do
    jwk = JOSE.JWK.generate_key({:rsa, 2048})
    jwk |> JOSE.JWK.to_map() |> elem(1) |> Map.put("kid", kid)
  end

  def build_rs_token_with_alg(opts) when is_map(opts) do
    kid = Map.get(opts, :kid, "kid-#{System.unique_integer([:positive])}")
    alg = Map.get(opts, :alg, "RS256")
    claims = Map.fetch!(opts, :claims)

    jwk = JOSE.JWK.generate_key({:rsa, 2048})
    jwk_map = jwk |> JOSE.JWK.to_map() |> elem(1) |> Map.put("kid", kid)

    header = %{"alg" => alg, "kid" => kid}

    {_, token} =
      JOSE.JWT.sign(jwk, header, claims)
      |> JOSE.JWS.compact()

    {token, jwk_map}
  end

  def build_hs256_token(opts) when is_map(opts) do
    kid = Map.get(opts, :kid, "kid-#{System.unique_integer([:positive])}")
    secret = Map.get(opts, :secret, "mobile-id-token-secret")
    claims = Map.fetch!(opts, :claims)
    jwk = JOSE.JWK.from_oct(secret)

    {_, token} =
      JOSE.JWT.sign(jwk, %{"alg" => "HS256", "kid" => kid}, claims)
      |> JOSE.JWS.compact()

    token
  end

  def build_none_token(opts) when is_map(opts) do
    header =
      %{"alg" => "none", "typ" => "JWT"}
      |> maybe_put_claim("kid", Map.get(opts, :kid))

    payload = Map.fetch!(opts, :claims)

    [
      Base.url_encode64(Jason.encode!(header), padding: false),
      Base.url_encode64(Jason.encode!(payload), padding: false),
      ""
    ]
    |> Enum.join(".")
  end

  def build_token_with_segments(segments) when is_list(segments), do: Enum.join(segments, ".")

  def base64url_json(map) when is_map(map),
    do: map |> Jason.encode!() |> Base.url_encode64(padding: false)

  def put_jwks_cache_with_timestamp(:google, jwks, fetched_at)
      when is_list(jwks) and is_integer(fetched_at) do
    :persistent_term.put(@google_cache_key, {jwks, fetched_at})
  end

  def put_jwks_cache_with_timestamp(:apple, jwks, fetched_at)
      when is_list(jwks) and is_integer(fetched_at) do
    :persistent_term.put(@apple_cache_key, {jwks, fetched_at})
  end

  def put_jwks_cache(:google, jwks) when is_list(jwks) do
    :persistent_term.put(@google_cache_key, {jwks, System.system_time(:second)})
  end

  def put_jwks_cache(:apple, jwks) when is_list(jwks) do
    :persistent_term.put(@apple_cache_key, {jwks, System.system_time(:second)})
  end

  def clear_jwks_cache(:google), do: :persistent_term.erase(@google_cache_key)
  def clear_jwks_cache(:apple), do: :persistent_term.erase(@apple_cache_key)

  def with_transport_error(name, reason, fun) when is_function(fun, 0) do
    previous = Req.default_options()
    Req.default_options(plug: {Req.Test, name}, retry: false)

    Req.Test.stub(name, fn conn ->
      Req.Test.transport_error(conn, reason)
    end)

    try do
      fun.()
    after
      Req.default_options(previous)
    end
  end

  def with_req_stub(name, stub_fun, fun) when is_function(stub_fun, 1) and is_function(fun, 0) do
    previous = Req.default_options()
    Req.default_options(plug: {Req.Test, name}, retry: false)
    Req.Test.stub(name, stub_fun)

    try do
      fun.()
    after
      Req.default_options(previous)
    end
  end

  defp maybe_put_claim(claims, _key, nil), do: claims
  defp maybe_put_claim(claims, key, value), do: Map.put(claims, key, value)

  defp default_email_verified(opts) do
    if Map.get(opts, :email), do: true, else: nil
  end
end
