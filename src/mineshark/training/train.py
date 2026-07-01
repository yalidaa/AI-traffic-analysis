import argparse
import os
import random
from collections import Counter
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score
from torch.optim import AdamW
from torch.utils.data import DataLoader, WeightedRandomSampler

from mineshark.data.dataset import (
    TrafficDataset,
    cap_samples_per_source,
    load_samples_from_dirs,
    load_samples_from_ppi_dirs,
    split_samples,
    split_samples_by_source,
)
from mineshark.models.traffic_transformer import TrafficTransformer
from mineshark.training.losses import JointLoss


PROJECT_ROOT = Path(__file__).resolve().parents[3]

EXPERIMENT_PRESETS = {
    "custom": {},
    "base": {
        "data_format": "log",
        "malware_dir": "datasets/experiments/logs_malware_base",
        "benign_dir": "datasets/raw/logs_benign",
        "save_path": "checkpoints/v_latest_ablation_base.pt",
        "split_mode": "by_source",
        "balanced_sampling": 1,
        "batch_size": 32,
        "epochs": 20,
        "triplet_margin": 0.5,
        "cls_weight": 1.0,
        "triplet_weight": 1.0,
    },
    "latest": {
        "data_format": "log",
        "malware_dir": "datasets/raw/logs_malware",
        "benign_dir": "datasets/raw/logs_benign",
        "save_path": "checkpoints/v_latest_main.pt",
        "split_mode": "by_source",
        "balanced_sampling": 1,
        "batch_size": 32,
        "epochs": 20,
        "triplet_margin": 0.5,
        "cls_weight": 1.0,
        "triplet_weight": 1.0,
    },
    "cross_domain": {
        "data_format": "ppi",
        "malware_dir": "datasets/processed/cesnet_ppi/malware",
        "benign_dir": "datasets/processed/cesnet_ppi/benign",
        "save_path": "checkpoints/v_latest_cross_domain.pt",
        "split_mode": "random",
        "balanced_sampling": 1,
        "batch_size": 32,
        "epochs": 20,
    },
    "ppi_local_latest": {
        "data_format": "ppi",
        "malware_dir": "datasets/experiments/ppi/local_malware_latest",
        "benign_dir": "datasets/experiments/ppi/local_benign",
        "save_path": "checkpoints/v_latest_ppi_local.pt",
        "split_mode": "by_source",
        "balanced_sampling": 1,
        "batch_size": 32,
        "epochs": 20,
    },
    "ppi_hybrid_latest": {
        "data_format": "ppi",
        "malware_dir": "datasets/experiments/ppi/local_malware_latest",
        "benign_dir": "datasets/experiments/ppi/hybrid_benign",
        "save_path": "checkpoints/v_latest_ppi_hybrid.pt",
        "split_mode": "by_source",
        "balanced_sampling": 1,
        "batch_size": 32,
        "epochs": 20,
        "max_samples_per_source": 12000,
    },
    "tor_binary": {
        "data_format": "ppi",
        "malware_dir": "datasets/experiments/ppi/tor/risk",
        "benign_dir": "datasets/experiments/ppi/tor/normal",
        "save_path": "checkpoints/tor_binary_mineshark.pt",
        "split_mode": "by_source",
        "balanced_sampling": 1,
        "batch_size": 64,
        "epochs": 20,
        "target_fpr": 0.02,
        "negative_label_name": "normal_tor",
        "positive_label_name": "tor_risk_evidence",
    },
}


def resolve_path(path_str: str) -> str:
    path = Path(path_str)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return str(path.resolve())


def set_seed(seed: int):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


def move_eval_batch(batch, device):
    return {
        "sizes": batch["sizes"].to(device),
        "iats": batch["iats"].to(device),
        "dirs": batch["dirs"].to(device),
        "mask": batch["mask"].to(device),
        "label": batch["label"].to(device),
    }


def move_triplet_batch(batch, device):
    def move_branch(branch):
        return {
            "sizes": branch["sizes"].to(device),
            "iats": branch["iats"].to(device),
            "dirs": branch["dirs"].to(device),
            "mask": branch["mask"].to(device),
            "label": branch["label"].to(device),
        }

    return (
        move_branch(batch["anchor"]),
        move_branch(batch["positive"]),
        move_branch(batch["negative"]),
        batch["label"].to(device),
    )


def predict_scores(model, loader, device):
    model.eval()
    labels = []
    malware_probs = []

    with torch.no_grad():
        for batch in loader:
            batch = move_eval_batch(batch, device)
            _, logits = model(
                batch["sizes"],
                batch["iats"],
                batch["dirs"],
                attention_mask=batch["mask"],
            )
            labels.extend(batch["label"].cpu().tolist())
            probs = torch.softmax(logits, dim=1)
            malware_probs.extend(probs[:, 1].cpu().tolist())

    return labels, malware_probs


def metrics_at_threshold(labels, malware_probs, threshold: float):
    preds = [1 if prob >= threshold else 0 for prob in malware_probs]
    tp = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 1)
    fp = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 1)
    tn = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 0)
    fn = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 0)

    return {
        "threshold": float(threshold),
        "accuracy": accuracy_score(labels, preds),
        "precision": precision_score(labels, preds, zero_division=0),
        "recall": recall_score(labels, preds, zero_division=0),
        "f1": f1_score(labels, preds, labels=[0, 1], average="binary", zero_division=0),
        "fpr": fp / max(fp + tn, 1),
        "fnr": fn / max(fn + tp, 1),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "preds": preds,
    }


def select_threshold(labels, malware_probs, target_fpr: float):
    if not 0.0 <= target_fpr <= 1.0:
        raise ValueError("--target-fpr must be between 0.0 and 1.0")

    candidates = {0.0, 1.0, 0.5}
    for prob in malware_probs:
        value = float(prob)
        candidates.add(value)
        candidates.add(min(1.0, value + 1e-7))
    candidates = sorted(candidates)
    scored = [metrics_at_threshold(labels, malware_probs, threshold) for threshold in candidates]

    feasible = [item for item in scored if item["fpr"] <= target_fpr]
    pool = feasible or scored
    return max(
        pool,
        key=lambda item: (
            item["f1"],
            item["recall"],
            item["precision"],
            -item["fpr"],
            -abs(item["threshold"] - 0.5),
        ),
    )


def evaluate(model, loader, device, threshold: float = 0.5):
    labels, malware_probs = predict_scores(model, loader, device)
    metrics = metrics_at_threshold(labels, malware_probs, threshold)
    return metrics["accuracy"], metrics["f1"], labels, metrics["preds"]


def print_operating_metrics(name, metrics):
    print(
        f"{name} threshold={metrics['threshold']:.4f} "
        f"acc={metrics['accuracy']:.4f} precision={metrics['precision']:.4f} "
        f"recall={metrics['recall']:.4f} f1={metrics['f1']:.4f} "
        f"fpr={metrics['fpr']:.4f} fnr={metrics['fnr']:.4f} "
        f"tp={metrics['tp']} fp={metrics['fp']} tn={metrics['tn']} fn={metrics['fn']}"
    )


def count_labels(samples):
    ones = sum(1 for x in samples if x["label"] == 1)
    zeros = len(samples) - ones
    return zeros, ones


def print_split_stats(name, samples, negative_label_name="Benign", positive_label_name="Malware"):
    negative_count, positive_count = count_labels(samples)
    sources = Counter(sample.get("source", "unknown") for sample in samples)
    print(f"{name}={len(samples)} ({negative_label_name}={negative_count}, {positive_label_name}={positive_count})")
    for src, cnt in sorted(sources.items(), key=lambda x: x[0]):
        print(f"  - {src}: {cnt}")


def build_balanced_sampler(samples):
    labels = [sample["label"] for sample in samples]
    label_counts = Counter(labels)
    class_weights = {label: 1.0 / count for label, count in label_counts.items() if count > 0}
    sample_weights = [class_weights[label] for label in labels]
    return WeightedRandomSampler(
        weights=torch.tensor(sample_weights, dtype=torch.double),
        num_samples=len(sample_weights),
        replacement=True,
    )


def apply_experiment_preset(args, parser):
    preset = EXPERIMENT_PRESETS[args.experiment]
    for key, value in preset.items():
        if getattr(args, key) == parser.get_default(key):
            setattr(args, key, value)

    args.malware_dir = resolve_path(args.malware_dir)
    args.benign_dir = resolve_path(args.benign_dir)
    args.save_path = resolve_path(args.save_path)
    if args.init_checkpoint:
        args.init_checkpoint = resolve_path(args.init_checkpoint)
    return args


def load_initial_checkpoint(model, checkpoint_path: str, init_mode: str, device):
    if init_mode == "none" or not checkpoint_path:
        return

    checkpoint = torch.load(checkpoint_path, map_location=device, weights_only=False)
    state_dict = checkpoint.get("model_state_dict", checkpoint) if isinstance(checkpoint, dict) else checkpoint
    if init_mode == "encoder":
        state_dict = {key: value for key, value in state_dict.items() if not key.startswith("classifier_head.")}
    current_state = model.state_dict()
    compatible_state = {
        key: value
        for key, value in state_dict.items()
        if key in current_state and tuple(current_state[key].shape) == tuple(value.shape)
    }
    skipped = len(state_dict) - len(compatible_state)
    result = model.load_state_dict(compatible_state, strict=False)
    print(
        f"Initialized model from {checkpoint_path} with mode={init_mode}; "
        f"loaded_keys={len(compatible_state)}, skipped_keys={skipped}, "
        f"missing_keys={len(result.missing_keys)}, unexpected_keys={len(result.unexpected_keys)}"
    )


def main(args, parser):
    args = apply_experiment_preset(args, parser)
    set_seed(args.seed)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")
    print(f"Experiment preset: {args.experiment}")
    print(f"Data format: {args.data_format}")
    print(f"Malware dir: {args.malware_dir}")
    print(f"Benign dir: {args.benign_dir}")
    print(f"Negative label: {args.negative_label_name}")
    print(f"Positive label: {args.positive_label_name}")

    if args.data_format == "ppi":
        all_samples = load_samples_from_ppi_dirs(
            malware_dir=args.malware_dir,
            benign_dir=args.benign_dir,
            max_len=args.max_len,
            min_packets=args.min_packets,
            max_pkt_size=args.max_pkt_size,
            max_iat=args.max_iat,
            ppi_field=args.ppi_field,
        )
    else:
        all_samples = load_samples_from_dirs(
            malware_dir=args.malware_dir,
            benign_dir=args.benign_dir,
            max_len=args.max_len,
            min_packets=args.min_packets,
            max_pkt_size=args.max_pkt_size,
            max_iat=args.max_iat,
        )

    if args.max_samples_per_source > 0:
        original_total = len(all_samples)
        all_samples = cap_samples_per_source(
            all_samples,
            max_samples_per_source=args.max_samples_per_source,
            seed=args.seed,
        )
        print(f"Capped samples per source: {args.max_samples_per_source} (from {original_total} to {len(all_samples)})")

    if args.split_mode == "by_source":
        train_samples, val_samples, test_samples = split_samples_by_source(
            all_samples,
            test_size=args.test_size,
            val_size=args.val_size,
            seed=args.seed,
        )
    else:
        train_samples, val_samples, test_samples = split_samples(
            all_samples,
            test_size=args.test_size,
            val_size=args.val_size,
            seed=args.seed,
        )

    print(f"Loaded samples: total={len(all_samples)}")
    print(f"Split mode: {args.split_mode}")
    print_split_stats("Train", train_samples, args.negative_label_name, args.positive_label_name)
    print_split_stats("Val", val_samples, args.negative_label_name, args.positive_label_name)
    print_split_stats("Test", test_samples, args.negative_label_name, args.positive_label_name)

    train_set = TrafficDataset(train_samples, mode="train_triplet")
    val_set = TrafficDataset(val_samples, mode="eval")
    test_set = TrafficDataset(test_samples, mode="eval")

    if bool(args.balanced_sampling):
        train_sampler = build_balanced_sampler(train_samples)
        train_loader = DataLoader(
            train_set,
            batch_size=args.batch_size,
            sampler=train_sampler,
            num_workers=0,
        )
        print("Train sampler: WeightedRandomSampler (class-balanced)")
    else:
        train_loader = DataLoader(train_set, batch_size=args.batch_size, shuffle=True, num_workers=0)
        print("Train sampler: shuffle=True (unbalanced)")

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
        num_classes=2,
    ).to(device)
    load_initial_checkpoint(model, args.init_checkpoint, args.init_mode, device)

    criterion = JointLoss(
        triplet_margin=args.triplet_margin,
        cls_weight=args.cls_weight,
        triplet_weight=args.triplet_weight,
        label_smoothing=args.label_smoothing,
    )

    optimizer = AdamW(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)

    best_val_f1 = -1.0
    best_epoch = 0
    no_improve_epochs = 0
    os.makedirs(os.path.dirname(args.save_path) or ".", exist_ok=True)

    for epoch in range(1, args.epochs + 1):
        model.train()
        total_loss = 0.0
        total_cls = 0.0
        total_tri = 0.0
        steps = 0

        for batch in train_loader:
            anchor, positive, negative, labels = move_triplet_batch(batch, device)

            optimizer.zero_grad()

            anchor_proj, anchor_logits = model(
                anchor["sizes"],
                anchor["iats"],
                anchor["dirs"],
                attention_mask=anchor["mask"],
            )
            pos_proj, _ = model(
                positive["sizes"],
                positive["iats"],
                positive["dirs"],
                attention_mask=positive["mask"],
            )
            neg_proj, _ = model(
                negative["sizes"],
                negative["iats"],
                negative["dirs"],
                attention_mask=negative["mask"],
            )

            loss, cls_loss, tri_loss = criterion(anchor_proj, pos_proj, neg_proj, anchor_logits, labels)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), args.grad_clip)
            optimizer.step()

            total_loss += loss.item()
            total_cls += cls_loss.item()
            total_tri += tri_loss.item()
            steps += 1

        train_loss = total_loss / max(steps, 1)
        train_cls = total_cls / max(steps, 1)
        train_tri = total_tri / max(steps, 1)

        val_acc, val_f1, _, _ = evaluate(model, val_loader, device)
        print(
            f"Epoch {epoch:03d} | "
            f"train_loss={train_loss:.4f} (cls={train_cls:.4f}, tri={train_tri:.4f}) | "
            f"val_acc={val_acc:.4f} val_f1={val_f1:.4f}"
        )

        if val_f1 > best_val_f1 + args.early_stop_min_delta:
            val_labels, val_probs = predict_scores(model, val_loader, device)
            calibrated = select_threshold(val_labels, val_probs, target_fpr=args.target_fpr)
            best_val_f1 = val_f1
            best_epoch = epoch
            no_improve_epochs = 0
            torch.save(
                {
                    "model_state_dict": model.state_dict(),
                    "config": vars(args),
                    "best_val_f1": best_val_f1,
                    "best_epoch": best_epoch,
                    "calibrated_threshold": calibrated["threshold"],
                    "calibration_target_fpr": args.target_fpr,
                    "negative_label_name": args.negative_label_name,
                    "positive_label_name": args.positive_label_name,
                    "validation_operating_metrics": {key: value for key, value in calibrated.items() if key != "preds"},
                },
                args.save_path,
            )
        else:
            no_improve_epochs += 1

        if no_improve_epochs >= args.early_stop_patience:
            print(
                f"Early stopping triggered at epoch {epoch:03d} "
                f"(no val_f1 improvement for {args.early_stop_patience} epochs)."
            )
            break

    print(f"Best model saved to: {args.save_path} (best_epoch={best_epoch}, val_f1={best_val_f1:.4f})")

    checkpoint = torch.load(args.save_path, map_location=device, weights_only=False)
    model.load_state_dict(checkpoint["model_state_dict"])

    calibrated_threshold = float(checkpoint.get("calibrated_threshold", args.decision_threshold))
    val_metrics = checkpoint.get("validation_operating_metrics")
    if val_metrics:
        print_operating_metrics("Validation calibrated", val_metrics)

    test_labels, test_probs = predict_scores(model, test_loader, device)
    default_metrics = metrics_at_threshold(test_labels, test_probs, args.decision_threshold)
    calibrated_metrics = metrics_at_threshold(test_labels, test_probs, calibrated_threshold)

    print_operating_metrics("Test default", default_metrics)
    print_operating_metrics("Test calibrated", calibrated_metrics)
    print(
        classification_report(
            test_labels,
            calibrated_metrics["preds"],
            labels=[0, 1],
            target_names=[args.negative_label_name, args.positive_label_name],
            digits=4,
            zero_division=0,
        )
    )


def build_parser():
    parser = argparse.ArgumentParser(description="Train Deep-MineShark with Transformer + Triplet")
    parser.add_argument(
        "--experiment",
        type=str,
        choices=sorted(EXPERIMENT_PRESETS.keys()),
        default="custom",
        help="Named preset for base/latest/cross_domain experiments.",
    )
    parser.add_argument("--malware-dir", type=str, default="datasets/raw/logs_malware")
    parser.add_argument("--benign-dir", type=str, default="datasets/raw/logs_benign")
    parser.add_argument("--save-path", type=str, default="checkpoints/deep_mineshark_best.pt")
    parser.add_argument("--negative-label-name", type=str, default="Benign")
    parser.add_argument("--positive-label-name", type=str, default="Malware")
    parser.add_argument("--init-checkpoint", type=str, default="")
    parser.add_argument(
        "--init-mode",
        type=str,
        choices=["none", "compatible", "encoder"],
        default="none",
        help="Optional model initialization: compatible loads all matching weights, encoder skips classifier_head.",
    )

    parser.add_argument("--max-len", type=int, default=128)
    parser.add_argument("--min-packets", type=int, default=3)
    parser.add_argument("--max-pkt-size", type=int, default=2000)
    parser.add_argument("--max-iat", type=float, default=10.0)

    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--lr", type=float, default=2e-4)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    parser.add_argument("--grad-clip", type=float, default=1.0)

    parser.add_argument("--embed-dim", type=int, default=128)
    parser.add_argument("--num-heads", type=int, default=4)
    parser.add_argument("--num-layers", type=int, default=2)
    parser.add_argument("--ff-dim", type=int, default=256)
    parser.add_argument("--dropout", type=float, default=0.1)

    parser.add_argument("--triplet-margin", type=float, default=0.5)
    parser.add_argument("--cls-weight", type=float, default=1.0)
    parser.add_argument("--triplet-weight", type=float, default=1.0)
    parser.add_argument("--label-smoothing", type=float, default=0.0)
    parser.add_argument(
        "--decision-threshold",
        type=float,
        default=0.5,
        help="Default positive-class probability threshold used as a baseline report.",
    )
    parser.add_argument(
        "--target-fpr",
        type=float,
        default=0.05,
        help="Maximum validation false-positive rate used to calibrate the saved operating threshold.",
    )

    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--val-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--split-mode", type=str, choices=["random", "by_source"], default="by_source")
    parser.add_argument("--balanced-sampling", type=int, choices=[0, 1], default=1)
    parser.add_argument("--early-stop-patience", type=int, default=3)
    parser.add_argument("--early-stop-min-delta", type=float, default=1e-4)
    parser.add_argument("--data-format", type=str, choices=["log", "ppi"], default="log")
    parser.add_argument("--ppi-field", type=str, default="PPI")
    parser.add_argument(
        "--max-samples-per-source",
        type=int,
        default=0,
        help="If > 0, cap each (label, source) bucket before splitting.",
    )
    return parser


def cli():
    parser = build_parser()
    main(parser.parse_args(), parser)


if __name__ == "__main__":
    cli()
