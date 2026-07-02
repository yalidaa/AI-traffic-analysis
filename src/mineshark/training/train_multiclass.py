from __future__ import annotations

import argparse
import json
import os
import random
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
import torch
from sklearn.metrics import accuracy_score, f1_score
from torch.optim import AdamW
from torch.utils.data import DataLoader, WeightedRandomSampler

from mineshark.data.dataset import (
    TrafficDataset,
    load_multiclass_samples_from_ppi_dirs,
    split_samples,
)
from mineshark.models.traffic_transformer import TrafficTransformer


TOR_CW_PRESET = {
    "data_dir": ["datasets/experiments/ppi/tor/wflib_cw"],
    "save_path": "checkpoints/tor_cw_multiclass_baseline.pt",
    "output_dir": "outputs/tor_data_runs/cw_multiclass_baseline",
    "task_name": "tor_cw_multiclass",
    "max_samples_per_class": 20,
    "epochs": 1,
    "batch_size": 32,
    "embed_dim": 64,
    "num_heads": 4,
    "num_layers": 1,
    "ff_dim": 128,
}


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def move_batch(batch: dict[str, torch.Tensor], device: torch.device) -> dict[str, torch.Tensor]:
    return {
        "sizes": batch["sizes"].to(device),
        "iats": batch["iats"].to(device),
        "dirs": batch["dirs"].to(device),
        "mask": batch["mask"].to(device),
        "label": batch["label"].to(device),
    }


def predict_probabilities(model, loader, device: torch.device) -> tuple[list[int], np.ndarray]:
    model.eval()
    labels: list[int] = []
    probs: list[list[float]] = []
    with torch.no_grad():
        for batch in loader:
            batch = move_batch(batch, device)
            _, logits = model(
                batch["sizes"],
                batch["iats"],
                batch["dirs"],
                attention_mask=batch["mask"],
            )
            labels.extend(batch["label"].cpu().tolist())
            probs.extend(torch.softmax(logits, dim=1).cpu().tolist())
    return labels, np.asarray(probs, dtype=np.float32)


def topk_accuracy(labels: list[int], probs: np.ndarray, k: int) -> float:
    if len(labels) == 0:
        return 0.0
    k = min(k, probs.shape[1])
    topk = np.argsort(probs, axis=1)[:, -k:]
    return float(np.mean([label in row for label, row in zip(labels, topk)]))


def multiclass_metrics(labels: list[int], probs: np.ndarray) -> dict[str, float]:
    preds = probs.argmax(axis=1).tolist() if probs.size else []
    return {
        "accuracy": float(accuracy_score(labels, preds)) if labels else 0.0,
        "macro_f1": float(f1_score(labels, preds, average="macro", zero_division=0)) if labels else 0.0,
        "weighted_f1": float(f1_score(labels, preds, average="weighted", zero_division=0)) if labels else 0.0,
        "top1_accuracy": topk_accuracy(labels, probs, 1),
        "top5_accuracy": topk_accuracy(labels, probs, 5),
    }


def write_training_summary(summary: dict[str, Any], output_dir: str | Path) -> str:
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    path = target / "train_summary.json"
    path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(path)


def build_balanced_sampler(samples: list[dict[str, Any]]) -> WeightedRandomSampler:
    labels = [int(sample["label"]) for sample in samples]
    label_counts = Counter(labels)
    weights = [1.0 / label_counts[label] for label in labels]
    return WeightedRandomSampler(torch.tensor(weights, dtype=torch.double), len(weights), replacement=True)


def apply_preset(args: argparse.Namespace, parser: argparse.ArgumentParser) -> argparse.Namespace:
    if args.preset != "tor_cw_multiclass":
        return args
    for key, value in TOR_CW_PRESET.items():
        if getattr(args, key) == parser.get_default(key):
            setattr(args, key, value)
    if args.data_dir is None:
        args.data_dir = list(TOR_CW_PRESET["data_dir"])
    return args


def print_split(name: str, samples: list[dict[str, Any]], class_names: list[str]) -> None:
    counts = Counter(int(sample["label"]) for sample in samples)
    detail = ", ".join(f"{class_names[label]}={count}" for label, count in sorted(counts.items()))
    print(f"{name}={len(samples)} ({detail})")


def train_multiclass(args: argparse.Namespace, parser: argparse.ArgumentParser | None = None) -> dict[str, Any]:
    if parser is not None:
        args = apply_preset(args, parser)
    set_seed(args.seed)

    data_dirs = [str(Path(item).resolve()) for item in args.data_dir]
    device = torch.device("cuda" if torch.cuda.is_available() and not args.cpu else "cpu")
    samples, class_names, class_to_idx = load_multiclass_samples_from_ppi_dirs(
        data_dirs,
        max_len=args.max_len,
        min_packets=args.min_packets,
        max_pkt_size=args.max_pkt_size,
        max_iat=args.max_iat,
        ppi_field=args.ppi_field,
        label_field=args.label_field,
        max_samples_per_class=args.max_samples_per_class,
    )
    if args.max_samples_per_class > 0:
        print(f"Capped samples per class during load: {args.max_samples_per_class} (loaded {len(samples)})")
    if len(class_names) < 2:
        raise ValueError("Need at least two classes for multiclass training.")

    train_samples, val_samples, test_samples = split_samples(
        samples,
        test_size=args.test_size,
        val_size=args.val_size,
        seed=args.seed,
    )
    print(f"Using device: {device}")
    print(f"Task: {args.task_name}")
    print(f"Classes: {len(class_names)}")
    print_split("Train", train_samples, class_names)
    print_split("Val", val_samples, class_names)
    print_split("Test", test_samples, class_names)

    train_set = TrafficDataset(train_samples, mode="eval")
    val_set = TrafficDataset(val_samples, mode="eval")
    test_set = TrafficDataset(test_samples, mode="eval")
    train_sampler = build_balanced_sampler(train_samples) if args.balanced_sampling else None
    train_loader = DataLoader(
        train_set,
        batch_size=args.batch_size,
        shuffle=train_sampler is None,
        sampler=train_sampler,
        num_workers=0,
    )
    val_loader = DataLoader(val_set, batch_size=args.batch_size, shuffle=False, num_workers=0)
    test_loader = DataLoader(test_set, batch_size=args.batch_size, shuffle=False, num_workers=0)

    model = TrafficTransformer(
        vocab_size=args.max_pkt_size + 2,
        seq_len=args.max_len,
        embed_dim=args.embed_dim,
        num_heads=args.num_heads,
        num_layers=args.num_layers,
        ff_dim=args.ff_dim,
        dropout=args.dropout,
        num_classes=len(class_names),
    ).to(device)
    criterion = torch.nn.CrossEntropyLoss(label_smoothing=args.label_smoothing)
    optimizer = AdamW(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)

    best_val_macro_f1 = -1.0
    best_epoch = 0
    os.makedirs(os.path.dirname(args.save_path) or ".", exist_ok=True)
    for epoch in range(1, args.epochs + 1):
        model.train()
        total_loss = 0.0
        steps = 0
        for batch in train_loader:
            batch = move_batch(batch, device)
            optimizer.zero_grad()
            _, logits = model(
                batch["sizes"],
                batch["iats"],
                batch["dirs"],
                attention_mask=batch["mask"],
            )
            loss = criterion(logits, batch["label"])
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), args.grad_clip)
            optimizer.step()
            total_loss += float(loss.item())
            steps += 1

        val_labels, val_probs = predict_probabilities(model, val_loader, device)
        val_metrics = multiclass_metrics(val_labels, val_probs)
        print(
            f"Epoch {epoch:03d} | train_loss={total_loss / max(steps, 1):.4f} "
            f"| val_acc={val_metrics['accuracy']:.4f} val_macro_f1={val_metrics['macro_f1']:.4f}"
        )
        if val_metrics["macro_f1"] > best_val_macro_f1:
            best_val_macro_f1 = val_metrics["macro_f1"]
            best_epoch = epoch
            torch.save(
                {
                    "model_state_dict": model.state_dict(),
                    "config": vars(args),
                    "class_names": class_names,
                    "class_to_idx": class_to_idx,
                    "num_classes": len(class_names),
                    "best_epoch": best_epoch,
                    "best_val_macro_f1": best_val_macro_f1,
                    "validation_metrics": val_metrics,
                },
                args.save_path,
            )

    checkpoint = torch.load(args.save_path, map_location=device, weights_only=False)
    model.load_state_dict(checkpoint["model_state_dict"])
    test_labels, test_probs = predict_probabilities(model, test_loader, device)
    test_metrics = multiclass_metrics(test_labels, test_probs)
    print(f"Best model saved to: {args.save_path} (best_epoch={best_epoch})")
    print(
        f"Test acc={test_metrics['accuracy']:.4f} macro_f1={test_metrics['macro_f1']:.4f} "
        f"weighted_f1={test_metrics['weighted_f1']:.4f} top5={test_metrics['top5_accuracy']:.4f}"
    )
    summary = {
        "checkpoint": args.save_path,
        "class_count": len(class_names),
        "sample_count": len(samples),
        "best_epoch": best_epoch,
        "validation_metrics": checkpoint.get("validation_metrics", {}),
        "test_metrics": test_metrics,
    }
    summary["summary_path"] = write_training_summary(summary, args.output_dir)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train a Tor website-fingerprinting multiclass baseline.")
    parser.add_argument("--preset", default="", choices=["", "tor_cw_multiclass"])
    parser.add_argument("--data-dir", action="append")
    parser.add_argument("--save-path", default="checkpoints/tor_cw_multiclass_baseline.pt")
    parser.add_argument("--output-dir", default="outputs/tor_data_runs/cw_multiclass_baseline")
    parser.add_argument("--task-name", default="tor_cw_multiclass")
    parser.add_argument("--max-samples-per-class", type=int, default=0)
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--val-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-len", type=int, default=128)
    parser.add_argument("--min-packets", type=int, default=3)
    parser.add_argument("--max-pkt-size", type=int, default=2000)
    parser.add_argument("--max-iat", type=float, default=10.0)
    parser.add_argument("--embed-dim", type=int, default=128)
    parser.add_argument("--num-heads", type=int, default=4)
    parser.add_argument("--num-layers", type=int, default=2)
    parser.add_argument("--ff-dim", type=int, default=256)
    parser.add_argument("--dropout", type=float, default=0.1)
    parser.add_argument("--lr", type=float, default=1e-4)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    parser.add_argument("--grad-clip", type=float, default=1.0)
    parser.add_argument("--label-smoothing", type=float, default=0.0)
    parser.add_argument(
        "--balanced-sampling",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use class-balanced weighted sampling for training. Pass --no-balanced-sampling to disable.",
    )
    parser.add_argument("--ppi-field", default="PPI")
    parser.add_argument("--label-field", default="APP")
    parser.add_argument("--cpu", action="store_true")
    return parser


def cli() -> None:
    parser = build_parser()
    train_multiclass(parser.parse_args(), parser)


if __name__ == "__main__":
    cli()
