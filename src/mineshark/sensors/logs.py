from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


ZEEK_CONN_FALLBACK_FIELDS = [
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "local_orig",
    "local_resp",
    "missed_bytes",
    "history",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
    "tunnel_parents",
]


def _matches_ip(record: Dict[str, Any], ip: Optional[str]) -> bool:
    if not ip:
        return True
    return ip in {
        str(record.get("id.orig_h", "")),
        str(record.get("id.resp_h", "")),
        str(record.get("src_ip", "")),
        str(record.get("dest_ip", "")),
        str(record.get("srcip", "")),
        str(record.get("dstip", "")),
    }


def _matches_uid(record: Dict[str, Any], uid: Optional[str]) -> bool:
    return not uid or str(record.get("uid", "")) == uid


def _within_time(record: Dict[str, Any], start_time: Optional[str], end_time: Optional[str]) -> bool:
    if not start_time and not end_time:
        return True
    ts = str(record.get("ts") or record.get("timestamp") or record.get("@timestamp") or "")
    if not ts:
        return True
    if start_time and ts < start_time:
        return False
    if end_time and ts > end_time:
        return False
    return True


def iter_zeek_log(path: Path, fallback_fields: Optional[List[str]] = None) -> Iterable[Dict[str, Any]]:
    fields = fallback_fields or ZEEK_CONN_FALLBACK_FIELDS
    separator = "\t"

    if not path.exists():
        return

    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#separator"):
                if r"\x09" in line:
                    separator = "\t"
                continue
            if line.startswith("#fields"):
                fields = line.split(separator)[1:]
                continue
            if line.startswith("#"):
                continue

            parts = line.split(separator)
            record = {field: parts[idx] if idx < len(parts) else "" for idx, field in enumerate(fields)}
            yield record


def query_zeek_context(
    log_dir: Path,
    ip: Optional[str] = None,
    uid: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    log_name: str = "conn.log",
    limit: int = 50,
) -> Dict[str, Any]:
    path = log_dir / log_name if log_dir.is_dir() else log_dir
    events = []
    for record in iter_zeek_log(path):
        if not _matches_ip(record, ip):
            continue
        if not _matches_uid(record, uid):
            continue
        if not _within_time(record, start_time, end_time):
            continue
        events.append(record)
        if len(events) >= limit:
            break
    return {"source_file": str(path), "events": events}


def iter_suricata_eve(path: Path) -> Iterable[Dict[str, Any]]:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def query_suricata_alerts(
    eve_path: Path,
    ip: Optional[str] = None,
    signature: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    events = []
    for record in iter_suricata_eve(eve_path):
        if record.get("event_type") != "alert":
            continue
        if ip and ip not in {str(record.get("src_ip", "")), str(record.get("dest_ip", ""))}:
            continue
        alert = record.get("alert", {})
        if signature and signature.lower() not in str(alert.get("signature", "")).lower():
            continue
        if not _within_time(record, start_time, end_time):
            continue
        events.append(record)
        if len(events) >= limit:
            break
    return {"source_file": str(eve_path), "alerts": events}
