# Makefile for common research workstation tasks.

SHELL := /bin/bash

PYTHON ?= python3
IDS_DIR := src/ids-xai-audit

.PHONY: help lab-up lab-down docs-serve lint dataset-download dataset-preprocess

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

dataset-download: ## Download + SHA-256 check of CICIDS2017 (ids-xai-audit)
	$(PYTHON) $(IDS_DIR)/scripts/download_dataset.py

dataset-preprocess: ## Clean/split/balance/scale CICIDS2017 into data/processed
	$(PYTHON) $(IDS_DIR)/scripts/preprocess_dataset.py
