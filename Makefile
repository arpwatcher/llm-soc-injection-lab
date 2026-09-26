.PHONY: install lint test coverage check

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
