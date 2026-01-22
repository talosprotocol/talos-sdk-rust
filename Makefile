SHELL := /bin/bash

.PHONY: all build test lint sbom clean

all: build test

build:
	cargo build

test:
	cargo test

lint:
	cargo fmt --check
	cargo clippy -- -D warnings

sbom:
	which cargo-cyclonedx || cargo install cargo-cyclonedx
	cargo cyclonedx -f json

clean:
	cargo clean
