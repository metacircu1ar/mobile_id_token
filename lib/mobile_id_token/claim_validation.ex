defmodule MobileIdToken.ClaimValidation do
  @moduledoc false

  def normalize_client_ids(ids) when is_list(ids) do
    ids
    |> Enum.map(&to_string/1)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  def normalize_client_ids(ids) when is_binary(ids) do
    ids
    |> String.split([",", " "], trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  def normalize_client_ids(_ids), do: []

  def audience_allowed?(aud, allowed_audiences, azp \\ nil)

  def audience_allowed?(aud, allowed_audiences, azp)
      when is_binary(aud) and is_list(allowed_audiences) do
    aud in allowed_audiences and azp_allowed?(azp, allowed_audiences, [aud])
  end

  def audience_allowed?(audiences, allowed_audiences, azp)
      when is_list(audiences) and is_list(allowed_audiences) do
    cond do
      audiences == [] ->
        false

      Enum.any?(audiences, &(not is_binary(&1) or String.trim(&1) == "")) ->
        false

      not Enum.all?(audiences, &(&1 in allowed_audiences)) ->
        false

      true ->
        azp_allowed?(azp, allowed_audiences, audiences)
    end
  end

  def audience_allowed?(_aud, _allowed_audiences, _azp), do: false

  def valid_exp?(exp), do: is_integer(exp)

  def expired?(exp) when is_integer(exp), do: exp < DateTime.utc_now() |> DateTime.to_unix()
  def expired?(_exp), do: true

  def valid_sub?(sub) when is_binary(sub), do: String.trim(sub) != ""
  def valid_sub?(_sub), do: false

  def email_verified_truthy?(true), do: true
  def email_verified_truthy?("true"), do: true
  def email_verified_truthy?(_value), do: false

  defp azp_allowed?(nil, _allowed_audiences, _audiences), do: true

  defp azp_allowed?(azp, allowed_audiences, audiences)
       when is_binary(azp) and is_list(allowed_audiences) and is_list(audiences) do
    trimmed_azp = String.trim(azp)
    trimmed_azp != "" and trimmed_azp in allowed_audiences and trimmed_azp in audiences
  end

  defp azp_allowed?(_azp, _allowed_audiences, _audiences), do: false
end
