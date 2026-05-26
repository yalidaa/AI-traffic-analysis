from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


SCORE_FIELDS = {
    "malware_probability",
    "probability",
    "risk_score",
    "score",
    "confidence",
    "model_score",
    "ai_score",
    "p_malware",
}
TIME_FIELDS = {"@timestamp", "timestamp", "ts", "time", "generated_at", "event_time"}


def _iter_values(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        for item in value.values():
            yield from _iter_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_values(item)
    else:
        yield value


def _contains_ip(record: Dict[str, Any], ip: Optional[str]) -> bool:
    if not ip:
        return True
    return any(str(value) == ip for value in _iter_values(record))


def _find_first_by_key(record: Any, keys: set[str]) -> Any:
    if isinstance(record, dict):
        for key, value in record.items():
            if key in keys:
                return value
        for value in record.values():
            found = _find_first_by_key(value, keys)
            if found is not None:
                return found
    elif isinstance(record, list):
        for value in record:
            found = _find_first_by_key(value, keys)
            if found is not None:
                return found
    return None


def _first_score(record: Dict[str, Any]) -> Optional[float]:
    raw = _find_first_by_key(record, SCORE_FIELDS)
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _first_timestamp(record: Dict[str, Any]) -> Optional[str]:
    raw = _find_first_by_key(record, TIME_FIELDS)
    if raw is None:
        return None
    return str(raw)


def _within_time(record: Dict[str, Any], start_time: Optional[str], end_time: Optional[str]) -> bool:
    if not start_time and not end_time:
        return True
    timestamp = _first_timestamp(record)
    if not timestamp:
        return True
    if start_time and timestamp < start_time:
        return False
    if end_time and timestamp > end_time:
        return False
    return True


def _records_from_payload(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("alerts", "events", "items", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return [payload]
    return []


def load_ai_alert_records(path: Path) -> Tuple[List[Dict[str, Any]], int]:
    if not path.exists():
        return [], 0

    text = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not text:
        return [], 0

    try:
        return _records_from_payload(json.loads(text)), 0
    except json.JSONDecodeError:
        pass

    records: List[Dict[str, Any]] = []
    invalid_lines = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            invalid_lines += 1
            continue
        records.extend(_records_from_payload(payload))
    return records, invalid_lines


def query_mineshark_ai_alerts(
    alerts_path: Path,
    ip: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    min_probability: Optional[float] = 0.5,
    limit: int = 20,
) -> Dict[str, Any]:
    records, invalid_lines = load_ai_alert_records(alerts_path)
    selected = []
    for record in records:
        if not _contains_ip(record, ip):
            continue
        if not _within_time(record, start_time, end_time):
            continue
        score = _first_score(record)
        if score is not None and min_probability is not None and score < min_probability:
            continue
        item = dict(record)
        item.setdefault("_mineshark_score", score)
        item.setdefault("_mineshark_timestamp", _first_timestamp(record))
        selected.append(item)
        if len(selected) >= limit:
            break

    return {
        "source_file": str(alerts_path),
        "exists": alerts_path.exists(),
        "total_records": len(records),
        "invalid_lines": invalid_lines,
        "matched": len(selected),
        "alerts": selected,
        "empty": len(records) == 0,
        "error": None,
    }
