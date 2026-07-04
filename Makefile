# Canonical commands. The agent invokes these, never raw compose strings.
# Override the technique: make run TECHNIQUE=T1087.001
include versions.env
export

TECHNIQUE ?= T1059.004
LAB_DIR := lab/wazuh-docker/single-node

.PHONY: help host-prep lab-fetch lab-up lab-down verify run build vet reset

help: ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

host-prep: ## one-time host tweak (vm.max_map_count) + tooling check
	@bash scripts/host-prep.sh

lab-fetch: ## pull pinned Wazuh single-node + Atomic Red Team, install override
	@bash scripts/lab-fetch.sh

lab-up: ## bring the merged Wazuh stack + victim up
	@cd $(LAB_DIR) && docker compose up -d
	@echo "give the indexer ~60-90s, then: make verify"

lab-down: ## stop the stack (keeps data)
	@cd $(LAB_DIR) && docker compose down

verify: ## binary health check + canary — must pass before proceeding
	@bash scripts/verify-lab.sh
	@go run ./cmd/purpleloop canary || (echo "CANARY FAILED — pipeline broken" && false)

canary: ## run the pipeline positive control
	@go run ./cmd/purpleloop canary

build: ## compile everything
	@go build ./cmd/... ./internal/...

vet: ## static checks
	@go vet ./cmd/... ./internal/...

run: build ## validate one technique end-to-end (TECHNIQUE=...)
	@go run ./cmd/purpleloop run --technique $(TECHNIQUE)

reset: ## FULL teardown incl. volumes — clean slate for a retry
	@cd $(LAB_DIR) && docker compose down -v || true
	@echo "lab volumes removed. run lab-up to rebuild from clean."
