defmodule MobileIdToken.MixProject do
  use Mix.Project

  def project do
    [
      app: :mobile_id_token,
      version: "0.1.0",
      elixir: "~> 1.15",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description:
        "Verify Apple and Google mobile OAuth id_token JWTs with JWKS caching and claim checks",
      package: package(),
      source_url: "https://github.com/metacircu1ar/mobile_id_token",
      docs: [main: "readme", extras: ["README.md", "CHANGELOG.md"]]
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:joken, "~> 2.6"},
      {:req, "~> 0.5"},
      {:plug, "~> 1.0", only: :test},
      {:ex_doc, "~> 0.30", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      files: ~w(lib mix.exs README.md CHANGELOG.md LICENSE .formatter.exs),
      licenses: ["MIT"],
      links: %{
        "GitHub" => "https://github.com/metacircu1ar/mobile_id_token"
      }
    ]
  end
end
