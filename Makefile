# SecureDB Web Client — development tasks
#
# Quick start (zero config):
#   make up       # app + database in Docker — http://localhost:8080
# or for local development:
#   make config   # create config.yaml with a generated encryption key
#   make dev      # start the database (Docker) + run the app locally
#
# The compose stack is configured via environment variables; config.yaml
# (see config.example.yaml) is for host runs and real deployments.

SHELL := /bin/bash

BINARY  := bin/securedb
DB_SVCS := app-db

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- setup

.PHONY: config
config: ## Create config.yaml from config.example.yaml with a generated encryption key
	@if [ -f config.yaml ]; then echo "config.yaml already exists — not overwriting"; exit 1; fi
	@sed "s/^  encryption_key: \"\"/  encryption_key: \"$$(openssl rand -hex 32)\"/" config.example.yaml > config.yaml
	@echo "created config.yaml with generated encryption key — review the database section and set seed.admin.password before first boot"

.PHONY: key
key: ## Print a new 32-byte hex encryption key
	@openssl rand -hex 32

# ---------------------------------------------------------------- build & run

.PHONY: build
build: ## Build the server binary to bin/securedb
	go build -o $(BINARY) ./cmd/server

.PHONY: run
run: ## Run the app locally (configured via config.yaml)
	@if [ ! -f config.yaml ]; then \
		echo "no config.yaml — run 'make config' first"; exit 1; fi
	go run ./cmd/server

.PHONY: dev
dev: db-up ## Start the database in Docker, then run the app locally
	$(MAKE) run

# ---------------------------------------------------------------- quality

.PHONY: test
test: ## Run all tests
	go test ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: tidy
tidy: ## go mod tidy
	go mod tidy

.PHONY: check
check: vet test ## Vet + tests

# ---------------------------------------------------------------- docker

.PHONY: up
up: ## Build and start the full stack (app + database)
	docker compose up --build -d
	@echo "SecureDB: http://localhost:8080  (admin@securedb.local / admin1234!)"

.PHONY: down
down: ## Stop the full stack
	docker compose down

.PHONY: db-up
db-up: ## Start only the application database
	docker compose up -d $(DB_SVCS)

.PHONY: db-down
db-down: ## Stop only the application database
	docker compose stop $(DB_SVCS)

.PHONY: logs
logs: ## Tail app container logs
	docker compose logs -f app

.PHONY: ps
ps: ## Show stack status
	docker compose ps

.PHONY: docker-build
docker-build: ## Build the app image only
	docker compose build app

.PHONY: reset
reset: ## DESTRUCTIVE: stop stack and delete the app database volume (reseeds on next start)
	docker compose down -v

# ---------------------------------------------------------------- misc

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf bin
