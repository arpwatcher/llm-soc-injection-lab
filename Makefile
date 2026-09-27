.PHONY: install lint test coverage check clean

install:
	pip install -r requirements.txt

lint:
	python -m ruff check .

test:
	python -m pytest -q

coverage:
	python -m coverage run -m pytest -q
	python -m coverage report -m

check: lint coverage

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov
