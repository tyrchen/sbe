build:
	@cargo build

# Unit + lib tests run under sbe (true dogfooding of the rust profile).
# Proxy integration tests run bare — they exercise the proxy server in
# isolation by binding 127.0.0.1:0 and connecting to that ephemeral
# port, which Landlock v4 cannot express; running them inside sbe would
# either require allowAllNetwork (defeats the purpose for this repo) or
# test nothing about sandboxing that the fixtures don't already cover.
test:
	@sbe run -- cargo nextest run --all-features -E 'not binary(proxy_integration)'
	@cargo nextest run --all-features -E 'binary(proxy_integration)'

fmt:
	@cargo +nightly fmt

lint:
	@cargo clippy -- -D warnings

check: fmt lint test

install:
	@cargo install --path apps/cli

release:
	@cargo release tag --execute
	@git cliff -o CHANGELOG.md
	@git commit -a -n -m "Update CHANGELOG.md" || true
	@git push origin master
	@cargo release push --execute

update-submodule:
	@git submodule update --init --recursive --remote

.PHONY: build test fmt lint check install release update-submodule
