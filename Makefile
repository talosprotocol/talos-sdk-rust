SHELL := /bin/bash

.PHONY: all build test lint sbom clean

all: build test

build:
\tcargo build

test:
\tcargo test

lint:
\tcargo fmt --check
\tcargo clippy -- -D warnings

sbom:
\twhich cargo-cyclonedx || cargo install cargo-cyclonedx
\tcargo cyclonedx -f json

clean:
\tcargo clean
