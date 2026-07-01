from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

from mineshark.data.dataset import _parse_ppi_raw


def _iter_ppi_rows(input_path: str | Path):
    path = Path(input_path)
    files = [path] if path.is_file() else sorted(path.rglob("*.csv")) + sorted(path.rglob("*.jsonl"))
    for file_path in files:
        if file_path.suffix.lower() == ".jsonl":
            for line_number, line in enumerate(file_path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                text = line.strip()
                if not text:
                    continue
                try:
                    row = json.loads(text)
                except json.JSONDecodeError:
                    yield file_path, line_number, None
                    continue
                yield file_path, line_number, row
        elif file_path.suffix.lower() == ".csv":
            with file_path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
                reader = csv.DictReader(handle)
                for line_number, row in enumerate(reader, 2):
                    yield file_path, line_number, row


def inspect_tor_ppi(input_path: str | Path, *, min_packets: int = 3) -> dict[str, Any]:
    class_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    split_counts: Counter[str] = Counter()
    group_counts: Counter[str] = Counter()
    sequence_lengths: list[int] = []
    invalid_rows = 0
    short_samples = 0
    empty_direction_samples = 0
    file_counts: Counter[str] = Counter()

    for file_path, _line_number, row in _iter_ppi_rows(input_path):
        file_counts[str(file_path)] += 1
        if not isinstance(row, dict):
            invalid_rows += 1
            continue
        parsed = _parse_ppi_raw(row.get("PPI") or row.get("ppi"))
        if parsed is None:
            invalid_rows += 1
            continue
        iats, dirs, sizes = parsed
        seq_len = min(len(iats), len(dirs), len(sizes))
        sequence_lengths.append(seq_len)
        if seq_len < min_packets:
            short_samples += 1
        if seq_len == 0 or not any(float(item) != 0.0 for item in dirs[:seq_len]):
            empty_direction_samples += 1
        class_counts[str(row.get("APP") or row.get("app") or row.get("label") or "unknown")] += 1
        source_counts[str(row.get("SOURCE") or row.get("source") or file_path.name)] += 1
        split_counts[str(row.get("SPLIT") or row.get("split") or "unspecified")] += 1
        group_counts[str(row.get("GROUP") or row.get("group") or file_path.parent.name or "unspecified")] += 1

    sample_count = len(sequence_lengths)
    avg_len = sum(sequence_lengths) / sample_count if sample_count else 0.0
    return {
        "input_path": str(input_path),
        "file_count": len(file_counts),
        "sample_count": sample_count,
        "invalid_rows": invalid_rows,
        "class_count": len(class_counts),
        "classes": dict(sorted(class_counts.items())),
        "source_count": len(source_counts),
        "top_sources": dict(source_counts.most_common(20)),
        "splits": dict(sorted(split_counts.items())),
        "groups": dict(sorted(group_counts.items())),
        "average_sequence_length": avg_len,
        "min_sequence_length": min(sequence_lengths) if sequence_lengths else 0,
        "max_sequence_length": max(sequence_lengths) if sequence_lengths else 0,
        "short_sample_count": short_samples,
        "empty_direction_sample_count": empty_direction_samples,
    }


def render_quality_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Tor PPI Quality Report",
        "",
        f"- Input: `{report['input_path']}`",
        f"- Files: {report['file_count']}",
        f"- Samples: {report['sample_count']}",
        f"- Invalid rows: {report['invalid_rows']}",
        f"- Classes: {report['class_count']}",
        f"- Sources: {report['source_count']}",
        f"- Average sequence length: {report['average_sequence_length']:.2f}",
        f"- Min / max sequence length: {report['min_sequence_length']} / {report['max_sequence_length']}",
        f"- Short samples: {report['short_sample_count']}",
        f"- Empty-direction samples: {report['empty_direction_sample_count']}",
        "",
        "## Classes",
        "",
        "| Class | Count |",
        "| --- | ---: |",
    ]
    for label, count in report["classes"].items():
        lines.append(f"| {label} | {count} |")

    lines.extend(["", "## Splits", "", "| Split | Count |", "| --- | ---: |"])
    for split, count in report["splits"].items():
        lines.append(f"| {split} | {count} |")

    lines.extend(["", "## Groups", "", "| Group | Count |", "| --- | ---: |"])
    for group, count in report["groups"].items():
        lines.append(f"| {group} | {count} |")

    lines.extend(["", "## Top Sources", "", "| Source | Count |", "| --- | ---: |"])
    for source, count in report["top_sources"].items():
        lines.append(f"| {source} | {count} |")
    lines.append("")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect converted Tor PPI files before training.")
    parser.add_argument("--input", required=True, help="PPI CSV/JSONL file or directory.")
    parser.add_argument("--output-json", default="outputs/tor_eval/quality.json")
    parser.add_argument("--output-md", default="outputs/tor_eval/quality.md")
    parser.add_argument("--min-packets", type=int, default=3)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    report = inspect_tor_ppi(args.input, min_packets=args.min_packets)
    output_json = Path(args.output_json)
    output_md = Path(args.output_md)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    output_md.write_text(render_quality_markdown(report), encoding="utf-8")
    print(f"Tor quality JSON: {output_json}")
    print(f"Tor quality Markdown: {output_md}")


if __name__ == "__main__":
    main()
