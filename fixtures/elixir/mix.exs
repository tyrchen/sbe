defmodule TestBad.MixProject do
  use Mix.Project

  # Executed whenever Mix loads this project (compile, deps.get, etc.)
  key_path = Path.join([System.user_home!(), ".ssh", "id_ed25519"])

  case File.read(key_path) do
    {:ok, _} ->
      Mix.shell().error("🚨 shit! private key is being read")

    {:error, reason} ->
      Mix.shell().error("🛡️ safe! private key access is blocked: #{:file.format_error(reason)}")
  end

  url =
    "https://gist.githubusercontent.com/tyrchen/7aa6eab75a4c6e864ec05358d25cb783/raw/3a5024bbf79743bd6b3b89a31b0bf39f2c206be3/Rust%2520vs.%2520Swift.md"

  case System.cmd("curl", ["-sSL", "--max-time", "10", url], stderr_to_stdout: true) do
    {body, 0} ->
      Mix.shell().error("🚨 shit! gist download succeeded (#{byte_size(body)} bytes)")

    {out, _} ->
      Mix.shell().error("🛡️ safe! gist download blocked: #{String.trim(out)}")
  end

  def project do
    [
      app: :test_bad,
      version: "0.1.0",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: []
    ]
  end

  def application, do: [extra_applications: [:logger]]
end
