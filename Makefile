SHELL := /bin/bash

PY_MODULE := limbo

ALL_PY_SRCS := $(shell find $(PY_MODULE) -name '*.py')

# Optionally overriden by the user, if they're using a virtual environment manager.
VENV ?= .venv

# On Windows, venv scripts/shims are under `Scripts` instead of `bin`.
VENV_BIN := $(VENV)/bin
ifeq ($(OS),Windows_NT)
	VENV_BIN := $(VENV)/Scripts
endif

NEEDS_VENV = $(VENV)/pyvenv.cfg

# Optionally overridden by the user/CI, to limit the installation to a specific
# subset of development dependencies.
INSTALL_EXTRA := dev

.PHONY: all
all:
	@echo "Run my targets individually!"

$(NEEDS_VENV): pyproject.toml
	uv venv $(VENV)
	uv pip install -e .[$(INSTALL_EXTRA)]

.PHONY: dev
dev: $(NEEDS_VENV)

.PHONY: lint
lint: $(NEEDS_VENV)
	. $(VENV_BIN)/activate && \
		ruff format --check $(ALL_PY_SRCS) && \
		ruff check $(ALL_PY_SRCS) && \
		mypy $(PY_MODULE)

.PHONY: reformat
reformat: $(NEEDS_VENV)
	. $(VENV_BIN)/activate && \
		ruff check --fix $(ALL_PY_SRCS) && \
		ruff format $(ALL_PY_SRCS)

.PHONY: edit
edit:
	$(EDITOR) $(ALL_PY_SRCS)

.PHONY: run
run: $(NEEDS_VENV)
	@./$(VENV_BIN)/python -m $(PY_MODULE) $(ARGS)

limbo-schema.json: $(NEEDS_VENV) $(PY_MODULE)/models.py
	$(MAKE) run ARGS="schema -o limbo-schema.json"

.PHONY: limbo.json
limbo.json: $(NEEDS_VENV)
	$(MAKE) run ARGS="compile -o limbo.json"

.PHONY: online-cases
online-cases: $(NEEDS_VENV)
	$(MAKE) run ARGS="online-cases"

.PHONY: testcases
testcases: $(NEEDS_VENV)
	$(MAKE) run ARGS="compile --testcases testcases/ --force"

.PHONY: build-harnesses
build-harnesses:
	$(MAKE) -C harness/gocryptox509
	$(MAKE) -C harness/openssl
	cargo build --bin rust-webpki-harness
	cargo build --bin rust-rustls-harness

.PHONY: test-go
test-go:
	$(MAKE) -C harness/gocryptox509
	$(MAKE) run ARGS="harness ./harness/gocryptox509/gocryptox509 --output ./results/go.json"

.PHONY: test-openssl
test-openssl:
	$(MAKE) -C harness/openssl openssl-1.1.1 openssl-3.0 openssl-3.2 openssl-3.3 openssl-3.4 openssl-3.5
	$(MAKE) run ARGS="harness --output ./results/openssl-1.1.1.json -- docker run --rm -i x509-limbo-openssl-1.1.1"
	$(MAKE) run ARGS="harness --output ./results/openssl-3.0.json -- docker run --rm -i x509-limbo-openssl-3.0"
	$(MAKE) run ARGS="harness --output ./results/openssl-3.2.json -- docker run --rm -i x509-limbo-openssl-3.2"
	$(MAKE) run ARGS="harness --output ./results/openssl-3.3.json -- docker run --rm -i x509-limbo-openssl-3.3"
	$(MAKE) run ARGS="harness --output ./results/openssl-3.4.json -- docker run --rm -i x509-limbo-openssl-3.4"
	$(MAKE) run ARGS="harness --output ./results/openssl-3.5.json -- docker run --rm -i x509-limbo-openssl-3.5"

.PHONY: test-rust-webpki
test-rust-webpki:
	@cargo build --bin rust-webpki-harness
	$(MAKE) run ARGS="harness ./target/debug/rust-webpki-harness --output ./results/rust-webpki.json"

.PHONY: test-rustls-webpki
test-rustls-webpki:
	@cargo build --bin rust-rustls-harness
	$(MAKE) run ARGS="harness ./target/debug/rust-rustls-harness --output ./results/rustls-webpki.json"

.PHONY: test-pyca-cryptography
test-pyca-cryptography: $(NEEDS_VENV)
	$(MAKE) run ARGS="harness --output ./results/pyca-cryptography.json -- ./$(VENV_BIN)/python ./harness/pyca-cryptography/main.py"

.PHONY: test-certvalidator
test-certvalidator: $(NEEDS_VENV)
	$(MAKE) run ARGS="harness --output ./results/certvalidator.json -- ./$(VENV_BIN)/python ./harness/certvalidator/main.py"

.PHONY: test-gnutls
test-gnutls:
	$(MAKE) run ARGS="harness --output ./results/gnutls.json -- ./$(VENV_BIN)/python ./harness/gnutls/test-gnutls"

.PHONY: test
test: test-go test-openssl test-rust-webpki test-rustls-webpki test-pyca-cryptography test-certvalidator test-gnutls

.PHONY: site
site: $(NEEDS_VENV)
	./$(VENV_BIN)/mkdocs build
