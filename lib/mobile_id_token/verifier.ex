defmodule MobileIdToken.Verifier do
  @moduledoc false

  alias MobileIdToken.JWKS

  @spec verify_id_token(String.t(), keyword(), keyword()) :: {:ok, map()} | {:error, atom()}
  def verify_id_token(id_token, opts, config)
      when is_binary(id_token) and is_list(opts) and is_list(config) do
    with {:ok, header} <- peek_header(id_token),
         :ok <- peek_payload(id_token),
         {:ok, kid} <- fetch_kid(header),
         {:ok, jwk_map} <- fetch_jwk(kid, config),
         {:ok, jwk} <- parse_jwk(jwk_map),
         {:ok, claims} <- verify_signature(jwk, id_token),
         validator when is_function(validator, 2) <- Keyword.fetch!(config, :claims_validator),
         {:ok, _claims} <- validator.(claims, opts) do
      {:ok, claims}
    else
      {:error, :invalid_token} -> {:error, :invalid_token}
      {:error, :missing_kid} -> {:error, :missing_kid}
      {:error, :invalid_signature} -> {:error, :invalid_signature}
      {:error, :jwk_not_found} -> {:error, :jwk_not_found}
      {:error, :jwks_unavailable} -> {:error, :jwks_unavailable}
      {:error, reason} -> {:error, reason}
      {:error, reason, _} -> {:error, reason}
      _ -> {:error, :invalid_token}
    end
  end

  defp peek_header(id_token) when is_binary(id_token) do
    case Joken.peek_header(id_token) do
      {:ok, header} when is_map(header) -> {:ok, header}
      _ -> {:error, :invalid_token}
    end
  rescue
    _ -> {:error, :invalid_token}
  end

  defp peek_payload(id_token) when is_binary(id_token) do
    case JOSE.JWT.peek_payload(id_token) do
      %JOSE.JWT{} -> :ok
      _ -> {:error, :invalid_token}
    end
  rescue
    _ -> {:error, :invalid_token}
  end

  defp fetch_kid(header) when is_map(header) do
    case Map.get(header, "kid") do
      kid when is_binary(kid) ->
        trimmed = String.trim(kid)

        if trimmed == "" do
          {:error, :missing_kid}
        else
          {:ok, trimmed}
        end

      _ ->
        {:error, :missing_kid}
    end
  end

  defp parse_jwk(jwk_map) when is_map(jwk_map) do
    {:ok, JOSE.JWK.from_map(jwk_map)}
  rescue
    _ -> {:error, :invalid_signature}
  end

  defp parse_jwk(_), do: {:error, :invalid_signature}

  defp verify_signature(jwk, id_token) do
    case JOSE.JWT.verify_strict(jwk, ["RS256"], id_token) do
      {true, %JOSE.JWT{fields: claims}, _} when is_map(claims) -> {:ok, claims}
      _ -> {:error, :invalid_signature}
    end
  rescue
    _ -> {:error, :invalid_signature}
  end

  defp fetch_jwk(kid, config) do
    uri = Keyword.fetch!(config, :jwks_uri)
    cache_key = Keyword.fetch!(config, :jwks_cache_key)
    ttl = Keyword.get(config, :jwks_ttl, 600)
    provider = Keyword.get(config, :provider, "provider")

    with {:ok, jwks} <- JWKS.fetch(uri, cache_key, ttl, provider: provider),
         %{} = jwk <- Enum.find(jwks, &(&1["kid"] == kid)) do
      {:ok, jwk}
    else
      {:error, :jwks_unavailable} ->
        {:error, :jwks_unavailable}

      _ ->
        with {:ok, jwks} <-
               JWKS.fetch(uri, cache_key, ttl, provider: provider, force_refresh: true),
             %{} = jwk <- Enum.find(jwks, &(&1["kid"] == kid)) do
          {:ok, jwk}
        else
          {:error, :jwks_unavailable} -> {:error, :jwks_unavailable}
          _ -> {:error, :jwk_not_found}
        end
    end
  end
end
