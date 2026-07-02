from __future__ import annotations

import argparse
import ast
import csv
import json
import math
import re
from pathlib import Path
from typing import Any, Iterable

import numpy as np

SUPPORTED_SUFFIXES = {".jsonl", ".json", ".csv", ".trace", ".cell", ".txt", ".npz", ".npy"}
NUMBER_RE = re.compile(r"[-+]?\d+(?:\.\d+)?")


def parse_sequence(raw: Any) -> list[Any] | None:
    if raw is None:
        return None
    if isinstance(raw, (list, tuple)):
        return list(raw)
    if isinstance(raw, (int, float)):
        return [raw]
    if not isinstance(raw, str):
        return None

    text = raw.strip()
    if not text:
        return None
    for parser in (json.loads, ast.literal_eval):
        try:
            value = parser(text)
        except Exception:
            continue
        if isinstance(value, (list, tuple)):
            return list(value)
        if isinstance(value, (int, float, str)):
            return [value]

    numbers = NUMBER_RE.findall(text)
    if numbers:
        return [float(item) for item in numbers]
    return [item for item in re.split(r"[\s,;|]+", text) if item]


def _first_sequence(record: dict[str, Any], names: tuple[str, ...]) -> list[Any] | None:
    for name in names:
        if name in record:
            parsed = parse_sequence(record[name])
            if parsed is not None:
                return parsed
    return None


def normalise_direction(value: Any) -> float:
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"out", "outgoing", "sent", "send", "client", "client_to_server", "c2s", "+", "+1", "1", "up"}:
            return 1.0
        if text in {"in", "incoming", "recv", "receive", "server", "server_to_client", "s2c", "-", "-1", "down"}:
            return -1.0
        if text in {"0", "pad", "padding", "none"}:
            return 0.0
    try:
        numeric = float(value)
    except Exception:
        return 0.0
    if numeric > 0:
        return 1.0
    if numeric < 0:
        return -1.0
    return 0.0


def _as_float_sequence(values: list[Any]) -> list[float] | None:
    output: list[float] = []
    for value in values:
        try:
            number = float(value)
        except Exception:
            return None
        if not math.isfinite(number):
            return None
        output.append(number)
    return output


def _to_plain_list(value: Any) -> list[Any]:
    if isinstance(value, np.ndarray):
        return value.reshape(-1).tolist()
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _compact_sequence(values: list[Any]) -> list[Any]:
    compacted = list(values)
    while compacted:
        tail = compacted[-1]
        try:
            if float(tail) == 0.0:
                compacted.pop()
                continue
        except Exception:
            pass
        break
    return compacted or list(values)


def _first_scalar(record: dict[str, Any], keys: tuple[str, ...]) -> Any | None:
    for key in keys:
        if key not in record:
            continue
        value = record[key]
        if value is None:
            continue
        if isinstance(value, str) and value == "":
            continue
        return value
    return None


def _row_to_record(row: Any, *, label: Any = None, source: str = "") -> dict[str, Any]:
    if isinstance(row, dict):
        record = dict(row)
    else:
        values = _compact_sequence(_to_plain_list(row))
        numeric = _as_float_sequence(values)
        record = {"directions": values}
        if numeric and any(0.0 < abs(item) < 1.0 for item in numeric):
            record["timestamps"] = [abs(item) for item in numeric]
            record["directions"] = [1 if item > 0 else -1 if item < 0 else 0 for item in numeric]
        elif numeric and any(abs(item) > 1.0 for item in numeric):
            record["sizes"] = [abs(item) for item in numeric]
    if label is not None:
        record.setdefault("label", label)
    if source:
        record.setdefault("source", source)
    return record


def _derive_iats(record: dict[str, Any], count: int) -> list[float] | None:
    explicit = _first_sequence(record, ("iats", "iat", "packet_iats", "cell_iats"))
    if explicit is not None:
        values = _as_float_sequence(explicit)
        if values is not None:
            return values

    timestamps = _first_sequence(record, ("timestamps", "timestamp", "times", "time", "ts", "packet_times"))
    if timestamps is None:
        return [0.0] * count
    values = _as_float_sequence(timestamps)
    if values is None or not values:
        return None
    iats = [0.0]
    for previous, current in zip(values, values[1:]):
        iats.append(max(0.0, current - previous))
    return iats


def record_to_ppi(
    record: dict[str, Any],
    *,
    source: str,
    default_app: str,
    default_size: int,
    min_packets: int,
    max_len: int,
) -> dict[str, str] | None:
    directions_raw = _first_sequence(
        record,
        ("directions", "direction", "dirs", "dir", "packet_directions", "cell_directions", "cells"),
    )
    if not directions_raw:
        return None

    directions = [normalise_direction(value) for value in directions_raw]
    iats = _derive_iats(record, len(directions))
    if iats is None:
        return None

    sizes_raw = _first_sequence(record, ("sizes", "size", "lengths", "packet_sizes", "cell_sizes", "pkt_sizes"))
    if sizes_raw is None:
        sizes = [float(default_size if direction != 0.0 else 0) for direction in directions]
    else:
        sizes = _as_float_sequence(sizes_raw)
        if sizes is None:
            return None

    seq_len = min(len(iats), len(directions), len(sizes), max_len)
    if seq_len < min_packets:
        return None

    label_value = _first_scalar(record, ("label", "app", "class", "site"))
    label = str(default_app if label_value is None else label_value)
    sample_source = str(record.get("source") or record.get("id") or source)
    ppi = [
        [float(value) for value in iats[:seq_len]],
        [float(value) for value in directions[:seq_len]],
        [float(abs(value)) for value in sizes[:seq_len]],
    ]
    return {"PPI": json.dumps(ppi, separators=(",", ":")), "APP": label, "SOURCE": sample_source}


def _iter_jsonl(path: Path) -> Iterable[tuple[dict[str, Any], str]]:
    for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        record = json.loads(text)
        if isinstance(record, dict):
            yield record, f"{path.name}:{line_number}"


def _iter_json(path: Path) -> Iterable[tuple[dict[str, Any], str]]:
    raw = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    records = raw.get("records") or raw.get("samples") or raw.get("traces") if isinstance(raw, dict) else raw
    if isinstance(records, dict):
        records = [records]
    if not isinstance(records, list):
        return
    for index, record in enumerate(records, start=1):
        if isinstance(record, dict):
            yield record, f"{path.name}:{index}"


def _iter_csv(path: Path) -> Iterable[tuple[dict[str, Any], str]]:
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.DictReader(handle)
        for index, record in enumerate(reader, start=1):
            yield dict(record), f"{path.name}:{index}"


def _iter_trace_file(path: Path) -> Iterable[tuple[dict[str, Any], str]]:
    timestamps: list[float] = []
    directions: list[Any] = []
    sizes: list[float] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        parts = re.split(r"[\s,;|]+", text)
        if len(parts) == 1:
            directions.append(parts[0])
        else:
            try:
                timestamps.append(float(parts[0]))
                directions.append(parts[1])
                if len(parts) >= 3:
                    sizes.append(float(parts[2]))
            except ValueError:
                directions.append(parts[-1])
    if directions:
        record: dict[str, Any] = {"directions": directions, "source": path.name}
        if timestamps:
            record["timestamps"] = timestamps
        if sizes and len(sizes) == len(directions):
            record["sizes"] = sizes
        yield record, path.name


def _find_np_array(arrays: dict[str, Any], names: tuple[str, ...]) -> Any | None:
    lowered = {key.lower(): key for key in arrays}
    for name in names:
        key = lowered.get(name.lower())
        if key is not None:
            return arrays[key]
    return None


def _array_len(value: Any) -> int:
    try:
        return len(value)
    except TypeError:
        return 0


def _label_at(labels: Any | None, index: int) -> Any | None:
    if labels is None:
        return None
    try:
        if _array_len(labels) == 0:
            return None
        return labels[index].item() if hasattr(labels[index], "item") else labels[index]
    except Exception:
        return None


def _iter_numpy_records(path: Path) -> Iterable[tuple[dict[str, Any], str]]:
    loaded = np.load(path, allow_pickle=True)
    if isinstance(loaded, np.lib.npyio.NpzFile):
        arrays = {key: loaded[key] for key in loaded.files}
        loaded.close()
    else:
        arrays = {"data": loaded}

    records = _find_np_array(arrays, ("records", "samples"))
    if records is not None and getattr(records, "dtype", None) is object:
        for index, item in enumerate(records, start=1):
            value = item.item() if hasattr(item, "item") else item
            if isinstance(value, dict):
                yield value, f"{path.name}:{index}"
        return

    data = _find_np_array(arrays, ("X", "x", "data", "traces", "trace", "directions", "dirs", "cells"))
    if data is None:
        return

    labels = _find_np_array(arrays, ("y", "label", "labels", "classes", "class", "site", "sites", "app", "apps"))
    times = _find_np_array(arrays, ("timestamps", "times", "time", "ts", "iats", "iat"))
    sizes = _find_np_array(arrays, ("sizes", "size", "lengths", "packet_sizes", "cell_sizes"))

    if getattr(data, "ndim", 1) == 1 and data.dtype == object:
        iterable = list(data)
    elif getattr(data, "ndim", 1) <= 1:
        iterable = [data]
    else:
        iterable = [data[index] for index in range(data.shape[0])]

    for index, row in enumerate(iterable):
        label = _label_at(labels, index)
        record = _row_to_record(row, label=label, source=f"{path.name}:{index + 1}")
        if times is not None and _array_len(times) > index:
            record.setdefault("timestamps", _to_plain_list(times[index]))
        if sizes is not None and _array_len(sizes) > index:
            record.setdefault("sizes", _to_plain_list(sizes[index]))
        yield record, f"{path.name}:{index + 1}"


def iter_records(path: Path) -> Iterable[tuple[dict[str, Any], str]]:
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        yield from _iter_jsonl(path)
    elif suffix == ".json":
        yield from _iter_json(path)
    elif suffix == ".csv":
        yield from _iter_csv(path)
    elif suffix in {".trace", ".cell", ".txt"}:
        yield from _iter_trace_file(path)
    elif suffix in {".npz", ".npy"}:
        yield from _iter_numpy_records(path)


def iter_input_files(input_path: str | Path) -> list[Path]:
    path = Path(input_path)
    if path.is_file():
        return [path]
    if not path.is_dir():
        raise FileNotFoundError(f"Tor input path not found: {path}")
    return sorted(item for item in path.rglob("*") if item.is_file() and item.suffix.lower() in SUPPORTED_SUFFIXES)


def convert_path(
    input_path: str | Path,
    output_csv: str | Path,
    *,
    default_app: str = "tor",
    default_size: int = 514,
    min_packets: int = 3,
    max_len: int = 128,
) -> dict[str, int]:
    files = iter_input_files(input_path)
    if not files:
        raise FileNotFoundError(f"No supported Tor trace files found under: {input_path}")

    output = Path(output_csv)
    output.parent.mkdir(parents=True, exist_ok=True)
    saved = 0
    skipped = 0
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["PPI", "APP", "SOURCE"])
        writer.writeheader()
        for file_path in files:
            for record, source in iter_records(file_path):
                row = record_to_ppi(
                    record,
                    source=source,
                    default_app=default_app,
                    default_size=default_size,
                    min_packets=min_packets,
                    max_len=max_len,
                )
                if row is None:
                    skipped += 1
                    continue
                writer.writerow(row)
                saved += 1
    return {"files": len(files), "saved": saved, "skipped": skipped}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Convert Tor website-fingerprinting traces to MineShark PPI CSV.")
    parser.add_argument("--input", required=True, help="Tor trace file or directory.")
    parser.add_argument("--output", required=True, help="Output PPI CSV path.")
    parser.add_argument("--default-app", default="tor", help="APP label used when a trace record has no label.")
    parser.add_argument("--default-size", type=int, default=514, help="Size used for direction-only Tor cell traces.")
    parser.add_argument("--min-packets", type=int, default=3)
    parser.add_argument("--max-len", type=int, default=128)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    stats = convert_path(
        args.input,
        args.output,
        default_app=args.default_app,
        default_size=args.default_size,
        min_packets=args.min_packets,
        max_len=args.max_len,
    )
    print(
        "Tor PPI export complete: "
        f"files={stats['files']}, saved={stats['saved']}, skipped={stats['skipped']}, output={args.output}"
    )


if __name__ == "__main__":
    main()
