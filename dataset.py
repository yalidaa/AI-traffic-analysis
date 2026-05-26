import ast
import csv
import glob
import gzip
import json
import os
import random
from collections import defaultdict
from typing import Dict, List, Sequence

import numpy as np
import torch
from sklearn.model_selection import train_test_split
from torch.utils.data import Dataset


def _parse_vector(raw: str, cast_type):
    if raw in {"(empty)", "-", ""}:
        return None
    try:
        return [cast_type(x) for x in raw.split(",")]
    except ValueError:
        return None


def parse_mineshark_log(
    file_path: str,
    label: int,
    max_len: int,
    min_packets: int,
    max_pkt_size: int,
    max_iat: float,
) -> List[Dict[str, Sequence]]:
    samples: List[Dict[str, Sequence]] = []
    source = os.path.basename(file_path)

    with open(file_path, "r", encoding="utf-8") as handle:
        for line in handle:
            if not line or line.startswith("#"):
                continue

            parts = line.rstrip("\n").split("\t")
            if len(parts) < 8:
                continue

            pkt_sizes = _parse_vector(parts[6], int)
            pkt_iats = _parse_vector(parts[7], float)
            if pkt_sizes is None or pkt_iats is None:
                continue
            if len(pkt_sizes) < min_packets:
                continue

            seq_len = min(len(pkt_sizes), len(pkt_iats), max_len)
            pkt_sizes = pkt_sizes[:seq_len]
            pkt_iats = pkt_iats[:seq_len]

            size_tokens = []
            dir_tokens = []
            iat_values = []
            attn_mask = [1] * seq_len

            for raw_size, raw_iat in zip(pkt_sizes, pkt_iats):
                abs_size = min(abs(raw_size), max_pkt_size)
                size_tokens.append(abs_size + 1)
                dir_tokens.append(1 if raw_size > 0 else 2 if raw_size < 0 else 0)
                iat_values.append(float(np.clip(raw_iat, 0.0, max_iat)))

            pad_len = max_len - seq_len
            if pad_len > 0:
                size_tokens.extend([0] * pad_len)
                dir_tokens.extend([0] * pad_len)
                iat_values.extend([0.0] * pad_len)
                attn_mask.extend([0] * pad_len)

            samples.append(
                {
                    "sizes": size_tokens,
                    "iats": iat_values,
                    "dirs": dir_tokens,
                    "mask": attn_mask,
                    "label": int(label),
                    "source": source,
                }
            )

    return samples


def load_samples_from_dirs(
    malware_dir: str,
    benign_dir: str,
    max_len: int = 128,
    min_packets: int = 3,
    max_pkt_size: int = 2000,
    max_iat: float = 10.0,
) -> List[Dict[str, Sequence]]:
    samples: List[Dict[str, Sequence]] = []

    for log_file in glob.glob(os.path.join(malware_dir, "*.log")):
        samples.extend(
            parse_mineshark_log(log_file, 1, max_len, min_packets, max_pkt_size, max_iat)
        )

    for log_file in glob.glob(os.path.join(benign_dir, "*.log")):
        samples.extend(
            parse_mineshark_log(log_file, 0, max_len, min_packets, max_pkt_size, max_iat)
        )

    return samples


def _iter_ppi_files(root_dir: str):
    patterns = ("*.csv", "*.jsonl", "*.csv.gz", "*.jsonl.gz")
    for pattern in patterns:
        for path in glob.glob(os.path.join(root_dir, "**", pattern), recursive=True):
            yield path


def _open_text(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="ignore")
    return open(path, "r", encoding="utf-8", errors="ignore")


def _parse_ppi_raw(ppi_raw):
    ppi_obj = ppi_raw
    if isinstance(ppi_raw, str):
        txt = ppi_raw.strip()
        if not txt:
            return None
        try:
            ppi_obj = json.loads(txt)
        except Exception:
            try:
                ppi_obj = ast.literal_eval(txt)
            except Exception:
                # Fallback for numpy pretty-printed arrays:
                # [[  0.  20. ...]
                #  [  1.  -1. ...]
                #  [517. 156. ...]]
                numbers = np.fromstring(
                    txt.replace("[", " ").replace("]", " "),
                    sep=" ",
                    dtype=np.float64,
                )
                if numbers.size >= 3 and numbers.size % 3 == 0:
                    arr = numbers.reshape(3, -1)
                    return arr[0].tolist(), arr[1].tolist(), arr[2].tolist()
                return None

    if isinstance(ppi_obj, dict):
        iats = ppi_obj.get("iat") or ppi_obj.get("iats")
        dirs = ppi_obj.get("dir") or ppi_obj.get("dirs")
        sizes = ppi_obj.get("size") or ppi_obj.get("sizes")
    elif isinstance(ppi_obj, (list, tuple)) and len(ppi_obj) >= 3:
        iats, dirs, sizes = ppi_obj[0], ppi_obj[1], ppi_obj[2]
    else:
        return None

    if not isinstance(iats, (list, tuple)):
        return None
    if not isinstance(dirs, (list, tuple)):
        return None
    if not isinstance(sizes, (list, tuple)):
        return None

    return list(iats), list(dirs), list(sizes)


def _build_sample_from_ppi(
    iats,
    dirs,
    sizes,
    label: int,
    source: str,
    max_len: int,
    min_packets: int,
    max_pkt_size: int,
    max_iat: float,
):
    seq_len = min(len(iats), len(dirs), len(sizes), max_len)
    if seq_len < min_packets:
        return None

    iats = iats[:seq_len]
    dirs = dirs[:seq_len]
    sizes = sizes[:seq_len]

    size_tokens = []
    dir_tokens = []
    iat_values = []
    attn_mask = [1] * seq_len

    for raw_iat, raw_dir, raw_size in zip(iats, dirs, sizes):
        try:
            size_int = int(float(raw_size))
            iat_float = float(raw_iat)
            dir_float = float(raw_dir)
        except Exception:
            return None

        abs_size = min(abs(size_int), max_pkt_size)
        size_tokens.append(abs_size + 1)
        dir_tokens.append(1 if dir_float > 0 else 2 if dir_float < 0 else 0)
        iat_values.append(float(np.clip(iat_float, 0.0, max_iat)))

    pad_len = max_len - seq_len
    if pad_len > 0:
        size_tokens.extend([0] * pad_len)
        dir_tokens.extend([0] * pad_len)
        iat_values.extend([0.0] * pad_len)
        attn_mask.extend([0] * pad_len)

    return {
        "sizes": size_tokens,
        "iats": iat_values,
        "dirs": dir_tokens,
        "mask": attn_mask,
        "label": int(label),
        "source": source,
    }


def parse_ppi_file(
    file_path: str,
    label: int,
    max_len: int,
    min_packets: int,
    max_pkt_size: int,
    max_iat: float,
    ppi_field: str = "PPI",
) -> List[Dict[str, Sequence]]:
    samples: List[Dict[str, Sequence]] = []
    source = os.path.basename(file_path)

    if file_path.endswith(".jsonl") or file_path.endswith(".jsonl.gz"):
        with _open_text(file_path) as handle:
            for line_idx, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                ppi_raw = obj.get(ppi_field) or obj.get("ppi")
                parsed = _parse_ppi_raw(ppi_raw)
                if parsed is None:
                    continue
                iats, dirs, sizes = parsed
                sample = _build_sample_from_ppi(
                    iats,
                    dirs,
                    sizes,
                    label=label,
                    source=source,
                    max_len=max_len,
                    min_packets=min_packets,
                    max_pkt_size=max_pkt_size,
                    max_iat=max_iat,
                )
                if sample is not None:
                    samples.append(sample)
        return samples

    with _open_text(file_path) as handle:
        reader = csv.DictReader(handle)
        for row_idx, row in enumerate(reader, start=1):
            ppi_raw = row.get(ppi_field) or row.get("ppi")
            parsed = _parse_ppi_raw(ppi_raw)
            if parsed is None:
                continue
            iats, dirs, sizes = parsed
            sample = _build_sample_from_ppi(
                iats,
                dirs,
                sizes,
                label=label,
                source=source,
                max_len=max_len,
                min_packets=min_packets,
                max_pkt_size=max_pkt_size,
                max_iat=max_iat,
            )
            if sample is not None:
                samples.append(sample)

    return samples


def load_samples_from_ppi_dirs(
    malware_dir: str,
    benign_dir: str,
    max_len: int = 128,
    min_packets: int = 3,
    max_pkt_size: int = 2000,
    max_iat: float = 10.0,
    ppi_field: str = "PPI",
) -> List[Dict[str, Sequence]]:
    samples: List[Dict[str, Sequence]] = []

    for ppi_file in _iter_ppi_files(malware_dir):
        samples.extend(
            parse_ppi_file(
                ppi_file,
                label=1,
                max_len=max_len,
                min_packets=min_packets,
                max_pkt_size=max_pkt_size,
                max_iat=max_iat,
                ppi_field=ppi_field,
            )
        )

    for ppi_file in _iter_ppi_files(benign_dir):
        samples.extend(
            parse_ppi_file(
                ppi_file,
                label=0,
                max_len=max_len,
                min_packets=min_packets,
                max_pkt_size=max_pkt_size,
                max_iat=max_iat,
                ppi_field=ppi_field,
            )
        )

    return samples


def cap_samples_per_source(
    samples: List[Dict[str, Sequence]],
    max_samples_per_source: int,
    seed: int = 42,
) -> List[Dict[str, Sequence]]:
    if max_samples_per_source <= 0:
        return samples

    rng = random.Random(seed)
    grouped = defaultdict(list)
    for sample in samples:
        grouped[(sample["label"], sample.get("source", "unknown"))].append(sample)

    capped = []
    for key in sorted(grouped.keys()):
        bucket = grouped[key]
        if len(bucket) > max_samples_per_source:
            capped.extend(rng.sample(bucket, max_samples_per_source))
        else:
            capped.extend(bucket)

    rng.shuffle(capped)
    return capped


def split_samples(
    samples: List[Dict[str, Sequence]],
    test_size: float = 0.2,
    val_size: float = 0.2,
    seed: int = 42,
):
    if not samples:
        raise ValueError("No valid samples were loaded.")

    labels = [sample["label"] for sample in samples]

    train_val, test = train_test_split(
        samples,
        test_size=test_size,
        random_state=seed,
        stratify=labels,
    )

    train_val_labels = [sample["label"] for sample in train_val]
    val_ratio = val_size / (1.0 - test_size)
    train, val = train_test_split(
        train_val,
        test_size=val_ratio,
        random_state=seed,
        stratify=train_val_labels,
    )

    return train, val, test


def _assign_sources_by_count(
    source_counts: Dict[str, int],
    test_size: float,
    val_size: float,
    rng: random.Random,
):
    keys = list(source_counts.keys())
    if len(keys) < 3:
        raise ValueError("Need at least 3 source files per class for by_source split.")

    rng.shuffle(keys)
    keys.sort(key=lambda x: source_counts[x], reverse=True)

    total = sum(source_counts.values())
    target = {
        "train": max(1, int(round(total * (1.0 - test_size - val_size)))),
        "val": max(1, int(round(total * val_size))),
        "test": max(1, int(round(total * test_size))),
    }
    target["train"] = max(1, total - target["val"] - target["test"])

    buckets = {
        "train": set(),
        "val": set(),
        "test": set(),
    }
    current = {"train": 0, "val": 0, "test": 0}

    seed_order = ["train", "val", "test"]
    for split, source in zip(seed_order, keys[:3]):
        buckets[split].add(source)
        current[split] += source_counts[source]

    for source in keys[3:]:
        deficits = []
        for split in ("train", "val", "test"):
            deficit = target[split] - current[split]
            ratio = deficit / max(target[split], 1)
            deficits.append((ratio, deficit, split))
        deficits.sort(reverse=True)
        chosen = deficits[0][2]
        buckets[chosen].add(source)
        current[chosen] += source_counts[source]

    return buckets["train"], buckets["val"], buckets["test"]


def split_samples_by_source(
    samples: List[Dict[str, Sequence]],
    test_size: float = 0.2,
    val_size: float = 0.2,
    seed: int = 42,
):
    if not samples:
        raise ValueError("No valid samples were loaded.")

    label_to_sources = defaultdict(set)
    for sample in samples:
        label_to_sources[sample["label"]].add(sample["source"])

    rng = random.Random(seed)
    split_map = {}
    for label in label_to_sources:
        source_counts = defaultdict(int)
        for sample in samples:
            if sample["label"] == label:
                source_counts[sample["source"]] += 1

        train_keys, val_keys, test_keys = _assign_sources_by_count(
            dict(source_counts), test_size, val_size, rng
        )
        split_map[label] = {
            "train": train_keys,
            "val": val_keys,
            "test": test_keys,
        }

    train = []
    val = []
    test = []
    for sample in samples:
        label = sample["label"]
        source = sample["source"]
        if source in split_map[label]["train"]:
            train.append(sample)
        elif source in split_map[label]["val"]:
            val.append(sample)
        elif source in split_map[label]["test"]:
            test.append(sample)

    if not train or not val or not test:
        raise ValueError("Grouped split produced an empty split; adjust split ratios.")

    return train, val, test


class TrafficDataset(Dataset):
    def __init__(self, samples: List[Dict[str, Sequence]], mode: str = "train_triplet"):
        if mode not in {"train_triplet", "eval"}:
            raise ValueError("mode must be 'train_triplet' or 'eval'")

        self.samples = samples
        self.mode = mode

        self.label_to_indices = {}
        for idx, item in enumerate(self.samples):
            label = item["label"]
            self.label_to_indices.setdefault(label, []).append(idx)

    def __len__(self):
        return len(self.samples)

    def _augment(self, sample: Dict[str, Sequence]):
        sizes = np.asarray(sample["sizes"], dtype=np.int64).copy()
        iats = np.asarray(sample["iats"], dtype=np.float32).copy()
        dirs = np.asarray(sample["dirs"], dtype=np.int64).copy()
        mask = np.asarray(sample["mask"], dtype=np.int64)

        valid = np.where(mask == 1)[0]
        for idx in valid:
            if random.random() < 0.15:
                sizes[idx] = 0
                dirs[idx] = 0

        if len(valid) > 0:
            noise = np.random.normal(loc=0.0, scale=0.005, size=len(valid)).astype(np.float32)
            iats[valid] = np.clip(iats[valid] + noise, 0.0, 10.0)

        return {
            "sizes": sizes.tolist(),
            "iats": iats.tolist(),
            "dirs": dirs.tolist(),
            "mask": sample["mask"],
            "label": sample["label"],
            "source": sample.get("source", "unknown"),
        }

    @staticmethod
    def _to_tensor(sample: Dict[str, Sequence]):
        return {
            "sizes": torch.tensor(sample["sizes"], dtype=torch.long),
            "iats": torch.tensor(sample["iats"], dtype=torch.float32).unsqueeze(-1),
            "dirs": torch.tensor(sample["dirs"], dtype=torch.long),
            "mask": torch.tensor(sample["mask"], dtype=torch.bool),
            "label": torch.tensor(sample["label"], dtype=torch.long),
        }

    def __getitem__(self, idx: int):
        anchor = self.samples[idx]

        if self.mode == "eval":
            return self._to_tensor(anchor)

        pos = self._augment(anchor)

        anchor_label = anchor["label"]
        negative_pool = []
        for label, indices in self.label_to_indices.items():
            if label != anchor_label:
                negative_pool.extend(indices)

        if negative_pool:
            neg_idx = random.choice(negative_pool)
        else:
            neg_idx = random.randrange(len(self.samples))
            while neg_idx == idx:
                neg_idx = random.randrange(len(self.samples))

        neg = self.samples[neg_idx]

        return {
            "anchor": self._to_tensor(anchor),
            "positive": self._to_tensor(pos),
            "negative": self._to_tensor(neg),
            "label": torch.tensor(anchor_label, dtype=torch.long),
        }
