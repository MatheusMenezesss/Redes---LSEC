# Experiments Directory Guide

Each experiment must live in its own folder under `experiments/` to avoid cross-contamination of datasets, scripts, and assumptions.

## Required structure per experiment

```text
experiments/<experiment-name>/
  README.md           # Problem statement, hypothesis, and reproducibility steps
  data/               # Small references or pointers to datasets (large files via LFS)
  notebooks/          # Optional analysis notebooks
  scripts/            # Automation scripts for setup/run/analysis
  results/            # Generated metrics, plots, and summaries
```

## Minimum documentation requirements

- Hypothesis and success criteria
- Infra/topology references
- Exact commands to reproduce
- Expected outputs and acceptance checks
- Known limitations and threats to validity
