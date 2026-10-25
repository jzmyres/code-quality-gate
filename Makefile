RUFF ?= $(shell $(PYTHON) -I qg.py tools path ruff)
PYTHON ?= python3

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := check

.PHONY: check lint test selfcheck

check: lint test selfcheck

lint:
	@tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	python_files=$$( $(PYTHON) -I qg.py inventory --list python ) || { echo 'lint: inventory could not list python files' >&2; exit 1; }; \
	test_files=$$( $(PYTHON) -I qg.py inventory --list test ) || { echo 'lint: inventory could not list test files' >&2; exit 1; }; \
	files=$$(printf '%s\n%s\n' "$$python_files" "$$test_files" | sed '/^$$/d'); \
	if [ -z "$$files" ]; then echo 'lint: inventory listed no Python files' >&2; exit 1; fi; \
	$(RUFF) check --no-cache $$files; \
	PYTHONPYCACHEPREFIX="$$tmp/pycache" $(PYTHON) -m py_compile $$files

test:
	@tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	set +e; \
	$(PYTHON) -I -m unittest discover -s tests > "$$tmp/output" 2>&1; \
	status=$$?; \
	set -e; \
	cat "$$tmp/output"; \
	if [ $$status -ne 0 ]; then exit $$status; fi; \
	if ! grep -Eq '^Ran [1-9][0-9]* tests? in ' "$$tmp/output"; then \
	  echo 'test: unittest selected no tests' >&2; \
	  exit 1; \
	fi

selfcheck:
	$(PYTHON) -I qg.py check
