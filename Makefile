# File: Makefile

.PHONY: help install test lint format clean docker-build docker-run migrations

help:
	@echo "Available commands:"
	@echo "  install     Install dependencies"
	@echo "  test        Run tests with coverage"
	@echo "  lint        Run linting checks"
	@echo "  format      Format code with black and isort"
	@echo "  clean       Remove cache files"
	@echo "  migrations  Create and run migrations"
	@echo "  docker-build Build Docker image"
	@echo "  docker-run   Run with Docker Compose"

install:
	pip install -r requirements.txt

test:
	pytest

test-verbose:
	pytest -v -s

lint:
	flake8 auth_integration users api tests
	mypy auth_integration users --ignore-missing-imports
	bandit -r auth_integration users -ll

format:
	black auth_integration users api tests
	isort auth_integration users api tests

clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf .pytest_cache/

migrations:
	python manage.py makemigrations
	python manage.py migrate

docker-build:
	docker build -t pefoma-backend .

docker-run:
	docker-compose up --build

superuser:
	python manage.py createsuperuser

runserver:
	python manage.py runserver

shell:
	python manage.py shell

collectstatic:
	python manage.py collectstatic --noinput

deploy-azure:
	@echo "Building and deploying to Azure..."
	docker build -t pefoma-backend .
	# Add Azure deployment commands here