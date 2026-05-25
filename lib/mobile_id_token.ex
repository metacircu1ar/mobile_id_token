defmodule MobileIdToken do
  @moduledoc """
  Verifies mobile OAuth `id_token` JWTs issued by Apple and Google.

  `verify/3` is the provider-agnostic entrypoint. It delegates to
  `MobileIdToken.Apple` and `MobileIdToken.Google`.
  """

  alias MobileIdToken.{Apple, Google}

  @type provider :: :apple | :google
  @typedoc """
  Verification options.

  - `:client_ids` - accepted `aud` values (list, comma-separated string, or single string)
  - `:nonce` - expected nonce (Apple expects this to be present; Google allows `nil`)

  The library does not read host app env vars directly; pass resolved client IDs explicitly.
  """
  @type verify_opts :: [client_ids: [String.t()] | String.t(), nonce: String.t() | nil]

  @type verify_error ::
          :invalid_token
          | :missing_kid
          | :jwk_not_found
          | :invalid_signature
          | :invalid_issuer
          | :missing_client_id
          | :invalid_audience
          | :token_expired
          | :invalid_claims
          | :email_not_verified
          | :invalid_nonce
          | :jwks_unavailable
          | :unsupported_provider

  @doc """
  Verifies an OAuth `id_token` for the given provider.

  ## Examples

      iex> MobileIdToken.verify(:google, token, client_ids: ["my-client-id"])
      {:ok, claims}

      iex> MobileIdToken.verify(:apple, token, client_ids: ["com.example.app"], nonce: "abc123")
      {:ok, claims}
  """
  @spec verify(provider(), String.t(), verify_opts()) :: {:ok, map()} | {:error, verify_error()}
  def verify(provider, id_token, opts \\ [])

  def verify(:apple, id_token, opts), do: Apple.verify_id_token(id_token, opts)
  def verify(:google, id_token, opts), do: Google.verify_id_token(id_token, opts)
  def verify(_provider, _id_token, _opts), do: {:error, :unsupported_provider}
end
