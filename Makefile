.PHONY: help install setup test lint format clean serve docs

# Default target
help:
	@echo "DataSentry PII Guardrail Tool"
	@echo "============================="
	@echo ""
	@echo "Available commands:"
	@echo "  install     - Install dependencies"
	@echo "  setup       - Run full setup (install + configure)"
	@echo "  test        - Run test suite"
	@echo "  lint        - Run code linting"
	@echo "  format      - Format code"
	@echo "  clean       - Clean temporary files"
	@echo "  serve       - Start API server"
	@echo "  docs        - Generate documentation"
	@echo ""

# Install dependencies
install:
	pip install -r requirements.txt
	python -m spacy download en_core_web_sm

# Full setup
setup:
	python setup.py

# Run tests
test:
	pytest tests/ -v

# Run tests with coverage
test-coverage:
	pytest tests/ -v --cov=datasentry --cov-report=html --cov-report=term

# Lint code
lint:
	flake8 datasentry/ tests/
	black --check datasentry/ tests/
	isort --check-only datasentry/ tests/

# Format code
format:
	black datasentry/ tests/
	isort datasentry/ tests/

# Clean temporary files
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf dist/
	rm -rf build/

# Start API server
serve:
	python -m datasentry.cli serve --reload

# Start API server in production mode
serve-prod:
	python -m datasentry.cli serve --host 0.0.0.0 --port 8000

# Generate documentation
docs:
	@echo "API documentation available at: http://localhost:8000/docs"
	@echo "Start the server with 'make serve' to view docs"

# Run quick PII detection test
test-detect:
	@echo "Testing PII detection..."
	@echo "My email is test@example.com and SSN is 123-45-6789" | python -m datasentry.cli detect

# Run quick masking test
test-mask:
	@echo "Testing PII masking..."
	@echo "Contact me at john@example.com or (555) 123-4567" | python -m datasentry.cli mask

# Validate policy configuration
validate-policies:
	python -m datasentry.cli validate-policies

# Generate compliance report
report:
	python -m datasentry.cli report --report-type detections --output report.json
	@echo "Report generated: report.json"

# Docker build (if Dockerfile exists)
docker-build:
	docker build -t datasentry:latest .

# Docker run
docker-run:
	docker run -p 8000:8000 datasentry:latest

# Install development dependencies
install-dev:
	pip install -r requirements.txt
	pip install pytest pytest-asyncio pytest-cov flake8 black isort

# Run all checks (lint, test, etc.)
check: lint test

# Build package
build:
	python -m build

# Install package in development mode
install-editable:
	pip install -e .