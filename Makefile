# Makefile for common research workstation tasks.

SHELL := /bin/bash

.PHONY: help lab-up lab-down docs-serve lint

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*##"; print "Available targets:"} /^[a-zA-Z_-]+:.*##/ {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

lab-up: ## Start the sample Containerlab topology
	containerlab deploy -t infra/containerlab/topologies/lab-sample.clab.yml

lab-down: ## Destroy the sample Containerlab topology
	containerlab destroy -t infra/containerlab/topologies/lab-sample.clab.yml --cleanup

docs-serve: ## Run MkDocs local development server
	mkdocs serve

lint: ## Run Python and YAML lint checks
	ruff check src experiments infra
	yamllint .
