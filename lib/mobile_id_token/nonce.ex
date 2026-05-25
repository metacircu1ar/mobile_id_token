defmodule MobileIdToken.Nonce do
  @moduledoc false

  def matches?(nonce_claim, expected_nonce)
      when is_binary(nonce_claim) and is_binary(expected_nonce) do
    trimmed_claim = String.trim(nonce_claim)
    trimmed_expected = String.trim(expected_nonce)

    if trimmed_expected == "" do
      false
    else
      hashed_expected =
        :crypto.hash(:sha256, trimmed_expected)
        |> Base.encode16(case: :lower)

      trimmed_claim == trimmed_expected or String.downcase(trimmed_claim) == hashed_expected
    end
  end

  def matches?(_nonce_claim, _expected_nonce), do: false
end
