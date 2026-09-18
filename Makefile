.PHONY: install test lint run mcp terraform-format

install:
	python -m pip install -e '.[dev]'

test:
	pytest --cov=sentinelops --cov-report=term-missing --cov-fail-under=80

lint:
	ruff check .

run:
	sentinelops-api

mcp:
	sentinelops-mcp

terraform-format:
	terraform fmt -recursive infrastructure/terraform
