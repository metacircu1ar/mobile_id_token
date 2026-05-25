defmodule MobileIdToken.JWKS do
  @moduledoc false
  require Logger

  @spec fetch(String.t(), term(), non_neg_integer(), keyword()) ::
          {:ok, [map()]} | {:error, :jwks_unavailable}
  def fetch(uri, cache_key, ttl_seconds, opts \\ []) when is_binary(uri) do
    force_refresh? = Keyword.get(opts, :force_refresh, false)
    provider = Keyword.get(opts, :provider, "provider")

    if force_refresh? do
      refresh(uri, cache_key, provider)
    else
      case :persistent_term.get(cache_key, nil) do
        {jwks, fetched_at} when is_list(jwks) and is_integer(fetched_at) ->
          if fresh?(fetched_at, ttl_seconds),
            do: {:ok, jwks},
            else: refresh(uri, cache_key, provider)

        _ ->
          refresh(uri, cache_key, provider)
      end
    end
  end

  defp refresh(uri, cache_key, provider) do
    case Req.get(uri) do
      {:ok, %Req.Response{status: 200, body: %{"keys" => keys}}} when is_list(keys) ->
        :persistent_term.put(cache_key, {keys, System.system_time(:second)})
        {:ok, keys}

      other ->
        Logger.warning("Failed to fetch #{provider} JWKS: #{inspect(other)}")
        {:error, :jwks_unavailable}
    end
  end

  defp fresh?(fetched_at, ttl_seconds) when is_integer(ttl_seconds) and ttl_seconds > 0 do
    System.system_time(:second) - fetched_at < ttl_seconds
  end

  defp fresh?(_fetched_at, _ttl_seconds), do: false
end
