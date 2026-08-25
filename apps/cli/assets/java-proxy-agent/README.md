# SBE Java proxy authentication agent

The JVM does not install a default `Authenticator` merely because
`http.proxyUser` and `http.proxyPassword` are set. Some embedded dependency
resolvers, including SBT launchers, therefore cannot answer an authenticated
HTTP CONNECT challenge.

SBE writes the embedded agent JAR into its private per-run directory. The
agent reads `SBE_PROXY_TOKEN`, validates the exact loopback host and port, and
answers only `Authenticator.RequestorType.PROXY` challenges for that endpoint.

Regenerate `java-proxy-auth-agent.jar.b64` from this directory with a JDK:

```sh
build_dir="$(mktemp -d)"
javac --release 8 -d "$build_dir/classes" src/dev/sbe/ProxyAuthAgent.java
jar --create --date=2026-01-01T00:00:00Z \
  --file "$build_dir/agent.jar" --manifest MANIFEST.MF \
  -C "$build_dir/classes" dev/sbe/ProxyAuthAgent.class \
  -C "$build_dir/classes" 'dev/sbe/ProxyAuthAgent$SbeProxyAuthenticator.class'
base64 < "$build_dir/agent.jar"
```

The committed payload is compiled with `--release 8` so it remains usable by
the Java versions supported by SBT 1.x. The decoded JAR has SHA-256 digest
`ff7b8835bb5d189a349d680e6ede1c6e44f3fdc0aa8b85647cf0964b958f8cf3`.
