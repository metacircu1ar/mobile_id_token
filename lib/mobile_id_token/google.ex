defmodule MobileIdToken.Google do
  @moduledoc """
  Verifies Google `id_token` JWTs using Google's JWKS endpoint.

  This module validates signature, issuer, audience, expiry, subject,
  email verification, and optional nonce.

  `:client_ids` must be passed by the host app.
  """

  alias MobileIdToken.{ClaimValidation, Nonce, Verifier}

  @issuers ["https://accounts.google.com", "accounts.google.com"]
  @jwks_uri "https://www.googleapis.com/oauth2/v3/certs"
  @jwks_cache_key {:mobile_id_token, :google_jwks}
  @jwks_ttl 600

  @doc """
  Verifies a Google `id_token`.

  ## Options

  - `:client_ids` (required)
  - `:nonce` (optional)

  Returns `{:ok, claims}` on success, otherwise `{:error, reason_atom}`.
  """
  def verify_id_token(id_token, opts \\ [])

  def verify_id_token(id_token, opts) when is_binary(id_token) and is_list(opts) do
    Verifier.verify_id_token(id_token, opts,
      provider: "Google",
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
      iss not in @issuers ->
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

      not verified_email_claim?(claims) ->
        {:error, :email_not_verified}

      not nonce_matches_expected?(claims, opts) ->
        {:error, :invalid_nonce}

      true ->
        {:ok, claims}
    end
  end

  defp validate_claims(_claims, _opts), do: {:error, :invalid_claims}

  defp verified_email_claim?(%{"email" => email} = claims) when is_binary(email) do
    String.trim(email) != "" and
      ClaimValidation.email_verified_truthy?(Map.get(claims, "email_verified"))
  end

  defp verified_email_claim?(_claims), do: false

  defp nonce_matches_expected?(claims, opts) do
    case Keyword.get(opts, :nonce) do
      expected_nonce when is_binary(expected_nonce) ->
        trimmed_expected_nonce = String.trim(expected_nonce)

        if trimmed_expected_nonce == "" do
          false
        else
          Nonce.matches?(Map.get(claims, "nonce"), trimmed_expected_nonce)
        end

      nil ->
        true

      _ ->
        false
    end
  end
end
