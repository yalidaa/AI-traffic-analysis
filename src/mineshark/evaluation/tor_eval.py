from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import torch
from torch.utils.data import DataLoader

from mineshark.data.dataset import TrafficDataset, load_samples_from_ppi_dirs
from mineshark.models.traffic_transformer import TrafficTransformer
from mineshark.training.train import metrics_at_threshold, predict_scores


def _format_percent(value: float) -> str:
    return f"{value * 100:.1f}%"


def _metrics_for_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    labels = [int(row["label"]) for row in rows]
    probs = [float(row["positive_probability"]) for row in rows]
    threshold = float(rows[0]["threshold"]) if rows else 0.5
    return {key: value for key, value in metrics_at_threshold(labels, probs, threshold).items() if key != "preds"}


def _group_metrics(rows: list[dict[str, Any]], group_by: str) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[str(row.get(group_by) or "unknown")].append(row)
    output = []
    for group, items in sorted(groups.items()):
        metrics = _metrics_for_rows(items)
        output.append({"group": group, "count": len(items), **metrics})
    return output


def _build_model_from_checkpoint(checkpoint: dict[str, Any], fallback_args: argparse.Namespace, device):
    config = checkpoint.get("config", {}) if isinstance(checkpoint, dict) else {}
    state_dict = checkpoint.get("model_state_dict", checkpoint) if isinstance(checkpoint, dict) else checkpoint
    model = TrafficTransformer(
        vocab_size=int(config.get("max_pkt_size", fallback_args.max_pkt_size)) + 2,
        seq_len=int(config.get("max_len", fallback_args.max_len)),
        embed_dim=int(config.get("embed_dim", fallback_args.embed_dim)),
        num_heads=int(config.get("num_heads", fallback_args.num_heads)),
        num_layers=int(config.get("num_layers", fallback_args.num_layers)),
        ff_dim=int(config.get("ff_dim", fallback_args.ff_dim)),
        dropout=float(config.get("dropout", fallback_args.dropout)),
        num_classes=2,
    ).to(device)
    model.load_state_dict(state_dict)
    return model, config


def evaluate_tor_checkpoint(args: argparse.Namespace) -> dict[str, Any]:
    device = torch.device("cuda" if torch.cuda.is_available() and not args.cpu else "cpu")
    checkpoint = torch.load(args.checkpoint, map_location=device, weights_only=False)
    model, config = _build_model_from_checkpoint(checkpoint, args, device)

    max_len = int(config.get("max_len", args.max_len))
    max_pkt_size = int(config.get("max_pkt_size", args.max_pkt_size))
    max_iat = float(config.get("max_iat", args.max_iat))
    min_packets = int(config.get("min_packets", args.min_packets))

    samples = load_samples_from_ppi_dirs(
        malware_dir=args.risk_dir,
        benign_dir=args.normal_dir,
        max_len=max_len,
        min_packets=min_packets,
        max_pkt_size=max_pkt_size,
        max_iat=max_iat,
        ppi_field=args.ppi_field,
    )
    dataset = TrafficDataset(samples, mode="eval")
    loader = DataLoader(dataset, batch_size=args.batch_size, shuffle=False, num_workers=0)
    labels, probs = predict_scores(model, loader, device)

    threshold = args.threshold
    if threshold is None:
        calibrated = checkpoint.get("calibrated_threshold") if isinstance(checkpoint, dict) else None
        threshold = float(calibrated if calibrated is not None else args.decision_threshold)
    metrics = {key: value for key, value in metrics_at_threshold(labels, probs, threshold).items() if key != "preds"}

    rows = []
    for sample, label, prob in zip(samples, labels, probs):
        rows.append(
            {
                "source": sample.get("source", "unknown"),
                "group": sample.get("source", "unknown"),
                "label": int(label),
                "actual": args.positive_label_name if int(label) == 1 else args.negative_label_name,
                "positive_probability": float(prob),
                "predicted": args.positive_label_name if float(prob) >= threshold else args.negative_label_name,
                "threshold": float(threshold),
            }
        )

    return {
        "checkpoint": str(args.checkpoint),
        "normal_dir": str(args.normal_dir),
        "risk_dir": str(args.risk_dir),
        "threshold": float(threshold),
        "negative_label_name": args.negative_label_name,
        "positive_label_name": args.positive_label_name,
        "sample_count": len(samples),
        "metrics": metrics,
        "groups": _group_metrics(rows, args.group_by),
        "rows": rows,
        "notes": [
            "Tor is anonymous encrypted communication, not an attack fact.",
            "Positive-class probability is Tor traffic risk evidence and requires analyst review.",
        ],
    }


def render_markdown(result: dict[str, Any]) -> str:
    metrics = result["metrics"]
    lines = [
        "# Tor Binary Evaluation Report",
        "",
        f"- Checkpoint: `{result['checkpoint']}`",
        f"- Normal dir: `{result['normal_dir']}`",
        f"- Risk dir: `{result['risk_dir']}`",
        f"- Samples: {result['sample_count']}",
        f"- Threshold: {result['threshold']:.4f}",
        f"- Negative label: `{result['negative_label_name']}`",
        f"- Positive label: `{result['positive_label_name']}`",
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Accuracy | {_format_percent(metrics['accuracy'])} |",
        f"| Precision | {_format_percent(metrics['precision'])} |",
        f"| Recall | {_format_percent(metrics['recall'])} |",
        f"| F1 | {_format_percent(metrics['f1'])} |",
        f"| FPR | {_format_percent(metrics['fpr'])} |",
        f"| FNR | {_format_percent(metrics['fnr'])} |",
        f"| TP | {metrics['tp']} |",
        f"| FP | {metrics['fp']} |",
        f"| TN | {metrics['tn']} |",
        f"| FN | {metrics['fn']} |",
        "",
        "## Groups",
        "",
        "| Group | Count | Accuracy | F1 | FPR | FNR |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for group in result["groups"]:
        lines.append(
            f"| {group['group']} | {group['count']} | {_format_percent(group['accuracy'])} | "
            f"{_format_percent(group['f1'])} | {_format_percent(group['fpr'])} | {_format_percent(group['fnr'])} |"
        )
    lines.extend(["", "## Boundary", ""])
    lines.extend(f"- {note}" for note in result["notes"])
    lines.append("")
    return "\n".join(lines)


def write_outputs(result: dict[str, Any], output_dir: str | Path) -> dict[str, str]:
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    metrics_path = target / "metrics.json"
    report_path = target / "report.md"
    metrics_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    report_path.write_text(render_markdown(result), encoding="utf-8")
    return {"metrics": str(metrics_path), "report": str(report_path)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate a MineShark Tor binary checkpoint on PPI directories.")
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--normal-dir", default="datasets/experiments/ppi/tor/normal")
    parser.add_argument("--risk-dir", default="datasets/experiments/ppi/tor/risk")
    parser.add_argument("--output-dir", default="outputs/tor_eval")
    parser.add_argument("--threshold", type=float)
    parser.add_argument("--decision-threshold", type=float, default=0.5)
    parser.add_argument("--negative-label-name", default="normal_tor")
    parser.add_argument("--positive-label-name", default="tor_risk_evidence")
    parser.add_argument("--group-by", default="source")
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--max-len", type=int, default=128)
    parser.add_argument("--min-packets", type=int, default=3)
    parser.add_argument("--max-pkt-size", type=int, default=2000)
    parser.add_argument("--max-iat", type=float, default=10.0)
    parser.add_argument("--embed-dim", type=int, default=128)
    parser.add_argument("--num-heads", type=int, default=4)
    parser.add_argument("--num-layers", type=int, default=2)
    parser.add_argument("--ff-dim", type=int, default=256)
    parser.add_argument("--dropout", type=float, default=0.1)
    parser.add_argument("--ppi-field", default="PPI")
    parser.add_argument("--cpu", action="store_true")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    result = evaluate_tor_checkpoint(args)
    outputs = write_outputs(result, args.output_dir)
    print(f"Samples: {result['sample_count']}")
    print(f"Accuracy: {result['metrics']['accuracy']:.4f}")
    print(f"F1: {result['metrics']['f1']:.4f}")
    for name, path in outputs.items():
        print(f"{name}: {path}")


if __name__ == "__main__":
    main()
