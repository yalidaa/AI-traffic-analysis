from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_REGISTRY = ROOT / "configs" / "datasets" / "tor_research_registry.json"


def load_research_registry(path: str | Path = DEFAULT_REGISTRY) -> dict[str, Any]:
    registry_path = Path(path)
    if not registry_path.exists():
        raise FileNotFoundError(f"Tor research registry not found: {registry_path}")
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    if not isinstance(registry, dict):
        raise ValueError("Tor research registry must be a JSON object.")
    datasets = registry.get("datasets")
    if not isinstance(datasets, list) or not datasets:
        raise ValueError("Tor research registry must contain a non-empty datasets list.")
    return registry


def load_local_manifest(path: str | Path) -> list[dict[str, Any]]:
    manifest_path = Path(path)
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    records = raw.get("datasets", raw) if isinstance(raw, dict) else raw
    if not isinstance(records, list):
        raise ValueError("Tor local manifest must be a list or {'datasets': [...]}.")
    return records


def validate_local_manifest(
    records: list[dict[str, Any]],
    registry: dict[str, Any] | None = None,
    *,
    require_existing_paths: bool = False,
) -> list[str]:
    registry = registry or load_research_registry()
    schema = registry.get("local_manifest_schema", {})
    required = schema.get("required_fields", [])
    allowed_formats = set(schema.get("allowed_formats", []))
    allowed_roles = set(schema.get("allowed_roles", []))
    dataset_ids = {item["id"] for item in registry.get("datasets", []) if "id" in item}

    errors: list[str] = []
    seen: set[str] = set()
    for index, record in enumerate(records, start=1):
        prefix = f"record[{index}]"
        if not isinstance(record, dict):
            errors.append(f"{prefix}: manifest entry must be an object")
            continue
        for field in required:
            if field not in record or record[field] in ("", None):
                errors.append(f"{prefix}: missing required field {field!r}")

        record_id = str(record.get("id", "")).strip()
        if record_id:
            if record_id in seen:
                errors.append(f"{prefix}: duplicate id {record_id!r}")
            seen.add(record_id)

        dataset_id = str(record.get("dataset_id", "")).strip()
        if dataset_id and dataset_id not in dataset_ids:
            errors.append(f"{prefix}: unknown dataset_id {dataset_id!r}")

        fmt = str(record.get("format", "")).strip().lower()
        if fmt and allowed_formats and fmt not in allowed_formats:
            errors.append(f"{prefix}: unsupported format {fmt!r}")

        role = str(record.get("role", "")).strip()
        if role and allowed_roles and role not in allowed_roles:
            errors.append(f"{prefix}: unsupported role {role!r}")

        path = str(record.get("path", "")).strip()
        if require_existing_paths and path and not Path(path).exists():
            errors.append(f"{prefix}: path does not exist: {path}")
    return errors


def render_registry_markdown(
    registry: dict[str, Any],
    local_records: list[dict[str, Any]] | None = None,
) -> str:
    lines = [
        "# Tor Dataset Inventory",
        "",
        f"- Project focus: {registry.get('project_focus', 'tor_encrypted_traffic')}",
        f"- Selection rule: {registry.get('selection_rule', '')}",
        "",
        "## Research Dataset Registry",
        "",
        "| Priority | Dataset | Venue | Task | Recommended role |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in registry.get("datasets", []):
        lines.append(
            "| {priority} | {dataset} | {venue} | {task} | {role} |".format(
                priority=item.get("priority", ""),
                dataset=item.get("id", ""),
                venue=item.get("venue", ""),
                task=item.get("task", ""),
                role=item.get("recommended_role", ""),
            )
        )

    if local_records is not None:
        lines.extend(
            [
                "",
                "## Local Manifest",
                "",
                "| ID | Dataset | Role | Label type | Format | Path |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for item in local_records:
            lines.append(
                "| {id} | {dataset_id} | {role} | {label_type} | {format} | {path} |".format(
                    id=item.get("id", ""),
                    dataset_id=item.get("dataset_id", ""),
                    role=item.get("role", ""),
                    label_type=item.get("label_type", ""),
                    format=item.get("format", ""),
                    path=item.get("path", ""),
                )
            )

    lines.extend(
        [
            "",
            "## Boundary",
            "",
            "Tor traffic is anonymous encrypted communication. MineShark-Tor studies passive website fingerprinting and "
            "encrypted-traffic behavior recognition; it must not describe Tor users as malicious by default.",
            "",
        ]
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate and render the MineShark Tor dataset registry.")
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY))
    parser.add_argument("--local-manifest")
    parser.add_argument("--output")
    parser.add_argument("--require-existing-paths", action="store_true")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    registry = load_research_registry(args.registry)
    local_records = None
    if args.local_manifest:
        local_records = load_local_manifest(args.local_manifest)
        errors = validate_local_manifest(
            local_records,
            registry,
            require_existing_paths=args.require_existing_paths,
        )
        if errors:
            raise SystemExit("\n".join(errors))
    markdown = render_registry_markdown(registry, local_records)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(markdown, encoding="utf-8")
        print(f"Tor dataset inventory: {output}")
    else:
        print(markdown)


if __name__ == "__main__":
    main()
