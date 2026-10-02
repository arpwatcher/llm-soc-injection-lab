.PHONY: install lint typecheck test coverage check clean

install:
	pip install -r requirements.txt

lint:
	python -m ruff check .

typecheck:
	python -m mypy .

test:
	python -m pytest -q

coverage:
	python -m coverage run -m pytest -q
	python -m coverage report -m

check: lint typecheck coverage

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache .mypy_cache .coverage htmlcov
