PYTHON ?= python3

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := check

.PHONY: check

check:
	$(PYTHON) -I qg.py check
