# Network Infrastructure Research Workstation Monorepo

This repository is a **research-first monorepo** for building, testing, and documenting network infrastructure experiments with reproducible workflows.

## Who this is for

- Network researchers and students
- Infrastructure engineers validating automation workflows
- Teams publishing reproducible lab artifacts and papers

## Repository layout

```text
.devcontainer/   # Standardized VS Code development container
.github/         # CI workflows and contribution templates
docs/            # MkDocs site, RFC process, and team documentation
infra/           # Infrastructure-as-Code (Containerlab, Ansible, Terraform)
src/             # Shared Python modules/utilities used by experiments
experiments/     # Isolated experiment folders with reproducibility notes
datasets/        # Dataset storage conventions and LFS-tracked assets
papers/          # LaTeX paper draft templates and publication assets
```

## Quick start

### 1) Clone and enter the repository

```bash
git clone <your-fork-or-origin-url>
cd Redes---LSEC
```

### 2) Install prerequisites

- Docker (for Containerlab and Dev Containers)
- Python 3.11+
- Make
- Git LFS (`git lfs install`)

### 3) Recommended: open in Dev Container

1. Open the repository in VS Code.
2. Run **Dev Containers: Reopen in Container**.
3. Wait for container initialization.

This ensures everyone shares the same toolchain (`tshark`, `ansible`, `ruff`, `yamllint`, etc.).

## Typical workflows

### Bring up/down a sample lab

```bash
make lab-up
make lab-down
```

### Run docs locally

```bash
make docs-serve
```

### Run quality checks

```bash
make lint
```

## Contributing

1. Create a focused branch.
2. Keep experiments isolated under `experiments/<name>/`.
3. Document hypothesis, method, and reproducibility steps.
4. Run `make lint` before opening a PR.
5. Fill in `.github/pull_request_template.md` completely.

## Experiment reproducibility checklist

- Scope and hypothesis stated clearly
- Topology and infra changes tracked in `infra/`
- Commands to reproduce results documented
- Dataset provenance and versioning documented
- Expected outputs and validation criteria included

## Data management

Binary research artifacts are tracked with Git LFS via `.gitattributes` (e.g., `*.pcap`, `*.qcow2`).
Avoid committing large binaries outside LFS-tracked patterns.

## Licensing and publication notes

Before external release, verify:

- No credentials or sensitive captures are included
- Dataset sharing rights and anonymization requirements are met
- Paper drafts in `papers/` match published methodology
