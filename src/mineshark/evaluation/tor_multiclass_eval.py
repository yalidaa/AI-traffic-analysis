from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
import torch
from sklearn.metrics import classification_report, confusion_matrix
from torch.utils.data import DataLoader

from mineshark.data.dataset import TrafficDataset, load_multiclass_samples_from_ppi_dirs
from mineshark.models.traffic_transformer import TrafficTransformer
from mineshark.training.train_multiclass import multiclass_metrics, predict_probabilities


def _format_percent(value: float) -> str:
    return f"{value * 100:.1f}%"


def _build_model_from_checkpoint(checkpoint: dict[str, Any], args: argparse.Namespace, device: torch.device):
    config = checkpoint.get("config", {})
    class_names = list(checkpoint.get("class_names") or [])
    num_classes = int(checkpoint.get("num_classes") or len(class_names))
    model = TrafficTransformer(
        vocab_size=int(config.get("max_pkt_size", args.max_pkt_size)) + 2,
        seq_len=int(config.get("max_len", args.max_len)),
        embed_dim=int(config.get("embed_dim", args.embed_dim)),
        num_heads=int(config.get("num_heads", args.num_heads)),
        num_layers=int(config.get("num_layers", args.num_layers)),
        ff_dim=int(config.get("ff_dim", args.ff_dim)),
        dropout=float(config.get("dropout", args.dropout)),
        num_classes=num_classes,
    ).to(device)
    model.load_state_dict(checkpoint["model_state_dict"])
    return model, config, class_names


def evaluate_multiclass(args: argparse.Namespace) -> dict[str, Any]:
    device = torch.device("cuda" if torch.cuda.is_available() and not args.cpu else "cpu")
    checkpoint = torch.load(args.checkpoint, map_location=device, weights_only=False)
    model, config, class_names = _build_model_from_checkpoint(checkpoint, args, device)
    raw_data_dirs = args.data_dir or ["datasets/experiments/ppi/tor/wflib_cw"]
    data_dirs = [str(Path(item).resolve()) for item in raw_data_dirs]
    samples, class_names, class_to_idx = load_multiclass_samples_from_ppi_dirs(
        data_dirs,
        max_len=int(config.get("max_len", args.max_len)),
        min_packets=int(config.get("min_packets", args.min_packets)),
        max_pkt_size=int(config.get("max_pkt_size", args.max_pkt_size)),
        max_iat=float(config.get("max_iat", args.max_iat)),
        ppi_field=args.ppi_field,
        label_field=args.label_field,
        class_names=class_names,
        max_samples_per_class=args.max_samples_per_class,
    )
    dataset = TrafficDataset(samples, mode="eval")
    loader = DataLoader(dataset, batch_size=args.batch_size, shuffle=False, num_workers=0)
    labels, probs = predict_probabilities(model, loader, device)
    preds = probs.argmax(axis=1).tolist() if probs.size else []
    metrics = multiclass_metrics(labels, probs)
    report = classification_report(
        labels,
        preds,
        labels=list(range(len(class_names))),
        target_names=class_names,
        output_dict=True,
        zero_division=0,
    )
    matrix = confusion_matrix(labels, preds, labels=list(range(len(class_names)))).tolist()
    top_indices = np.argsort(probs, axis=1)[:, -min(5, len(class_names)) :][:, ::-1] if probs.size else []
    rows = []
    for sample, label, pred, prob, topk in zip(samples, labels, preds, probs, top_indices):
        rows.append(
            {
                "source": sample.get("source", "unknown"),
                "actual": class_names[int(label)],
                "predicted": class_names[int(pred)],
                "confidence": float(prob[int(pred)]),
                "top5": [{"class": class_names[int(idx)], "probability": float(prob[int(idx)])} for idx in topk],
            }
        )
    return {
        "checkpoint": str(args.checkpoint),
        "data_dirs": data_dirs,
        "sample_count": len(samples),
        "class_count": len(class_names),
        "class_names": class_names,
        "class_to_idx": class_to_idx,
        "class_distribution": dict(sorted(Counter(sample["label_name"] for sample in samples).items())),
        "metrics": metrics,
        "classification_report": report,
        "confusion_matrix": matrix,
        "rows": rows,
        "notes": [
            "This is Tor encrypted traffic website-fingerprinting classification, not Tor malware detection.",
            "Predictions should be reported as traffic metadata risk evidence and reviewed with context.",
        ],
    }


def render_markdown(result: dict[str, Any]) -> str:
    metrics = result["metrics"]
    lines = [
        "# Tor Closed-World Multiclass Evaluation",
        "",
        f"- Checkpoint: `{result['checkpoint']}`",
        f"- Samples: {result['sample_count']}",
        f"- Classes: {result['class_count']}",
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Accuracy | {_format_percent(metrics['accuracy'])} |",
        f"| Macro-F1 | {_format_percent(metrics['macro_f1'])} |",
        f"| Weighted-F1 | {_format_percent(metrics['weighted_f1'])} |",
        f"| Top-1 Accuracy | {_format_percent(metrics['top1_accuracy'])} |",
        f"| Top-5 Accuracy | {_format_percent(metrics['top5_accuracy'])} |",
        "",
        "## Class Distribution",
        "",
        "| Class | Count |",
        "| --- | ---: |",
    ]
    for label, count in result["class_distribution"].items():
        lines.append(f"| {label} | {count} |")
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
    parser = argparse.ArgumentParser(description="Evaluate a Tor website-fingerprinting multiclass checkpoint.")
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--data-dir", action="append")
    parser.add_argument("--output-dir", default="outputs/tor_data_runs/cw_multiclass_baseline")
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
    parser.add_argument("--label-field", default="APP")
    parser.add_argument("--max-samples-per-class", type=int, default=0)
    parser.add_argument("--cpu", action="store_true")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    result = evaluate_multiclass(args)
    outputs = write_outputs(result, args.output_dir)
    print(f"Samples: {result['sample_count']}")
    print(f"Accuracy: {result['metrics']['accuracy']:.4f}")
    print(f"Macro-F1: {result['metrics']['macro_f1']:.4f}")
    for name, path in outputs.items():
        print(f"{name}: {path}")


if __name__ == "__main__":
    main()
