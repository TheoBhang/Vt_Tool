# --- Makefile ---
-include .env

.PHONY: help up down build pull deploy create-certs init

NETCHECK_CMD = ./scripts/check-network.sh

help:
	@echo "Available commands:"
	@echo "  up            - Start services"
	@echo "  down          - Stop services"
	@echo "  build         - Build Docker images"
	@echo "  pull          - Pull Docker images"
	@echo "  deploy        - Deploy application"
	@echo "  create-certs  - Generate TLS certificates"
	@echo "  init          - Initialize the project"

up:
	$(NETCHECK_CMD)
	@echo "Starting services..."
	@docker compose --env-file .env up -d

down:
	@echo "Stopping services..."
	@docker compose --env-file .env down --remove-orphans

build:
	@echo "Building images..."
	@docker compose --env-file .env build

pull:
	@echo "Pulling images..."
	@docker compose --env-file .env pull

deploy:
	$(NETCHECK_CMD)
	@echo "Deploying..."
	@./scripts/deploy.sh

create-certs:
	@echo "Generating certificates..."
	@./scripts/openssl-certificates-generator.sh

init:
	@echo "Initializing project..."
	@./scripts/init.sh
	@echo "Initialization complete."
