.PHONY: install lint typecheck test coverage audit check clean

install:
	pip install -r requirements.txt

lint:
	python -m ruff check .

typecheck:
	python -m mypy .

test:
	python -m pytest -q

coverage:
	python -m coverage run --branch -m pytest -q
	python -m coverage report -m

# checks pinned dependencies against known vulnerability databases - kept
# separate from `check` since it needs network access (queries PyPI's
# advisory data), unlike every other target here, which runs fully offline.
audit:
	python -m pip_audit -r requirements.txt

check: lint typecheck coverage

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache .mypy_cache .coverage htmlcov
