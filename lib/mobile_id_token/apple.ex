defmodule MobileIdToken.Apple do
  @moduledoc """
  Verifies Apple `id_token` JWTs using Apple's JWKS endpoint.

  This module validates signature, issuer, audience, expiry, subject,
  optional email verification, and nonce.

  `:client_ids` must be passed by the host app.
  """

  alias MobileIdToken.{ClaimValidation, Nonce, Verifier}

  @issuer "https://appleid.apple.com"
  @jwks_uri "https://appleid.apple.com/auth/keys"
  @jwks_cache_key {:mobile_id_token, :apple_jwks}
  @jwks_ttl 600

  @doc """
  Verifies an Apple `id_token`.

  ## Options

  - `:client_ids` (required)
  - `:nonce` (required)

  Returns `{:ok, claims}` on success, otherwise `{:error, reason_atom}`.
  """
  def verify_id_token(id_token, opts \\ [])

  def verify_id_token(id_token, opts) when is_binary(id_token) and is_list(opts) do
    Verifier.verify_id_token(id_token, opts,
      provider: "Apple",
      jwks_uri: @jwks_uri,
      jwks_cache_key: @jwks_cache_key,
      jwks_ttl: @jwks_ttl,
      claims_validator: &validate_claims/2
    )
  end

  def verify_id_token(_id_token, _opts), do: {:error, :invalid_token}

  defp validate_claims(%{"iss" => iss, "aud" => aud, "exp" => exp, "sub" => sub} = claims, opts) do
    allowed_audiences = ClaimValidation.normalize_client_ids(Keyword.get(opts, :client_ids, []))

    cond do
      iss != @issuer ->
        {:error, :invalid_issuer}

      allowed_audiences == [] ->
        {:error, :missing_client_id}

      not ClaimValidation.audience_allowed?(aud, allowed_audiences, Map.get(claims, "azp")) ->
        {:error, :invalid_audience}

      not ClaimValidation.valid_exp?(exp) ->
        {:error, :invalid_claims}

      ClaimValidation.expired?(exp) ->
        {:error, :token_expired}

      not ClaimValidation.valid_sub?(sub) ->
        {:error, :invalid_claims}

      not email_claim_verified_if_present?(claims) ->
        {:error, :email_not_verified}

      not nonce_matches_expected?(claims, opts) ->
        {:error, :invalid_nonce}

      true ->
        {:ok, claims}
    end
  end

  defp validate_claims(_claims, _opts), do: {:error, :invalid_claims}

  defp email_claim_verified_if_present?(claims) when is_map(claims) do
    case Map.get(claims, "email") do
      email when is_binary(email) and email != "" ->
        ClaimValidation.email_verified_truthy?(Map.get(claims, "email_verified"))

      _ ->
        true
    end
  end

  defp email_claim_verified_if_present?(_claims), do: false

  defp nonce_matches_expected?(claims, opts) do
    case Keyword.get(opts, :nonce) do
      expected_nonce when is_binary(expected_nonce) ->
        Nonce.matches?(Map.get(claims, "nonce"), expected_nonce)

      _ ->
        false
    end
  end
end
