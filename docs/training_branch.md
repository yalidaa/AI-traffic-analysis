# Training Branch

This branch is dedicated to research and iteration on the AI analysis module.

Scope:

- Traffic feature extraction and training data preparation.
- Model training, evaluation, and experiment tracking.
- AI alert generation and analysis quality improvements.
- Integration points between model outputs, RAG evidence, and security reports.

Current focus:

- The report generator now supports benign/low-risk control samples through `--include-benign-sample`
  or `--benign-log-file`.
- Report JSON and Markdown outputs include risk explanations, evidence strength, contrast margin,
  and an analyst review template for false-positive feedback.

Non-goals:

- Replacing the stable demo branch behavior without validation.
- Changing Wazuh deployment or production service assumptions unless required by AI analysis experiments.
