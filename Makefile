SHELL := /bin/bash

PY_MODULE := limbo

ALL_PY_SRCS := $(shell find $(PY_MODULE) -name '*.py')

# Optionally overriden by the user, if they're using a virtual environment manager.
VENV ?= env

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
	python -m venv $(VENV) --upgrade-deps
	$(VENV_BIN)/python -m pip install -e .[$(INSTALL_EXTRA)]

.PHONY: dev
dev: $(NEEDS_VENV)

.PHONY: lint
lint: $(NEEDS_VENV)
	. $(VENV_BIN)/activate && \
		black --check $(ALL_PY_SRCS) && \
		ruff $(ALL_PY_SRCS) && \
		mypy $(PY_MODULE)

.PHONY: reformat
reformat: $(NEEDS_VENV)
	. $(VENV_BIN)/activate && \
		ruff --fix $(ALL_PY_SRCS) && \
		black $(ALL_PY_SRCS)

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

.PHONY: testcases
testcases: $(NEEDS_VENV)
	$(MAKE) run ARGS="compile --testcases testcases/ --force"
