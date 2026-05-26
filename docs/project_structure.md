# Project Structure

This repository follows a Python `src/` layout.

```text
src/mineshark/
├── data/
├── models/
├── reporting/
└── training/
```

## Directory Roles

`src/mineshark/` contains importable Python package code.

`scripts/` contains thin wrappers for common command-line workflows.

`configs/` contains environment files, reporting knowledge, and future experiment configs.

`docs/` contains project handoff notes, dependency documentation, and reporting notes.

`datasets/` contains local raw and processed datasets. It is ignored by Git except for `.gitkeep` placeholders.

`checkpoints/` contains local model weights. It is ignored by Git except for `.gitkeep`.

`outputs/` contains generated reports and experiment outputs. It is ignored by Git except for `.gitkeep` placeholders.

## Local Artifact Policy

Large or generated artifacts should stay local:

```text
datasets/
checkpoints/
outputs/
```

Source code, docs, configs, scripts, and package metadata should be committed.
