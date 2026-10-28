PYTHON ?= python3

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := check

.PHONY: check mutation

check:
	$(PYTHON) -I qg.py check

mutation:
	$(PYTHON) -I tests/mutate_gate.py
