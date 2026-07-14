SHELL := /usr/bin/env bash

ROOT := ../../..
VENV ?= $(ROOT)/.venv
VENV_BIN := $(VENV)/bin
ifeq ($(OS),Windows_NT)
	VENV_BIN := $(VENV)/Scripts
endif

CRLS := bad_version.crl generalized_time_2025.crl missing_next_update.crl

.PHONY: assets
assets: $(CRLS)

%.crl: %.txt crl_cases_ca_key.pem ../scripts/generate_crl.py
	go run github.com/google/der-ascii/cmd/ascii2der@latest < $< > $@
	$(VENV_BIN)/python -m limbo._assets.scripts.generate_crl $@
