.PHONY: clean clean-test clean-pyc clean-build docs help
.DEFAULT_GOAL := help
define BROWSER_PYSCRIPT
import os, webbrowser, sys
try:
	from urllib import pathname2url
except:
	from urllib.request import pathname2url

webbrowser.open("file://" + pathname2url(os.path.abspath(sys.argv[1])))
endef
export BROWSER_PYSCRIPT

define PRINT_HELP_PYSCRIPT
import re, sys

for line in sys.stdin:
	match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT
BROWSER := uv run python -c "$$BROWSER_PYSCRIPT"

help:
	@python -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

clean: clean-build clean-pyc clean-test ## remove all build, test, coverage and Python artifacts


clean-build: ## remove build artifacts
	rm -fr build/
	rm -fr dist/
	rm -fr .eggs/
	rm -fr wolfssl/_ffi*
	find . -name '*.egg-info' -exec rm -fr {} +
	find . -name '*.egg' -exec rm -f {} +
	-cd lib/wolfssl && make clean

clean-pyc: ## remove Python file artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test: ## remove test and coverage artifacts
	rm -fr .tox/
	rm -f .coverage
	rm -fr htmlcov/

lint: ## check style with ruff
	uv run ruff check

test: ## run tests quickly with the default Python
	uv run py.test tests

check: test ## run tests quickly with the default Python

test-all: ## run tests on every Python version with uv
	for version in 3.10 3.11 3.12 3.13 3.14; do \
		echo "=== Python $$version ==="; \
		uv run --python $$version pytest tests || exit 1; \
	done

check-all: test-all ## run tests on every Python version with uv

cov:  ## check code coverage quickly with the default Python
	uv run pytest --cov=wolfcrypt tests
	uv run coverage report -m
	uv run coverage html
	$(BROWSER) htmlcov/index.html

docs: ## generate Sphinx HTML documentation, including API docs
	$(MAKE) -C docs clean
	uv run $(MAKE) -C docs html
	$(BROWSER) docs/_build/html/index.html

doctest: ## generate Sphinx HTML documentation, including API docs
	$(MAKE) -C docs clean
	uv run $(MAKE) -C docs doctest

servedocs: docs ## compile the docs watching for changes
	watchmedo shell-command -p '*.rst' -c '$(MAKE) -C docs html' -R -D .

dist: clean ## builds source and wheel package
	uv build --sdist

	./make/osx/build_wheels.sh

	./make/manylinux1/build_wheels.sh

	ls -l dist

release: ## package and upload a release
	twine upload dist/*
