build:
	@cargo build

test:
	@cargo nextest run --all-features

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
