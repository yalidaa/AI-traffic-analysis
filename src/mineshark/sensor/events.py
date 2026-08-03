from __future__ import annotations

import json
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

from mineshark.sensor.flow import CompletedFlow


SENSITIVE_EVIDENCE_FIELDS = {
    "payload",
    "payload_printable",
    "packet",
    "packet_info",
}


def build_ai_alert(
    flow: CompletedFlow,
    *,
    sensor_id: str,
    model_id: str,
    model_sha256: str,
    threshold: float,
    malware_probability: float,
    observed_at: datetime,
) -> dict[str, Any]:
    identity = {
        "sensor_id": sensor_id,
        "model_sha256": model_sha256,
        "flow": [
            flow.src_ip,
            flow.src_port,
            flow.dst_ip,
            flow.dst_port,
            flow.protocol,
            round(flow.started_at, 6),
        ],
    }
    event_id = sha256(json.dumps(identity, separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest()
    probability = float(malware_probability)
    return {
        "schema_version": 1,
        "event_type": "ai_alert",
        "event_id": event_id,
        "alert_id": event_id,
        "sensor_id": sensor_id,
        "observed_at": observed_at.isoformat(),
        "timestamp": observed_at.isoformat(),
        "flow": {
            "src_ip": flow.src_ip,
            "src_port": flow.src_port,
            "dst_ip": flow.dst_ip,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "started_at": flow.started_at,
            "ended_at": flow.ended_at,
            "close_reason": flow.close_reason,
        },
        "src_ip": flow.src_ip,
        "src_port": flow.src_port,
        "dst_ip": flow.dst_ip,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "model": {
            "model_id": model_id,
            "sha256": model_sha256,
            "threshold": float(threshold),
        },
        "prediction": "malware" if probability >= threshold else "benign",
        "malware_probability": probability,
        "risk_level": _risk_level(probability),
        "features": {
            "signed_packet_sizes": list(flow.signed_packet_sizes),
            "time_offsets": list(flow.time_offsets),
            "packet_count": len(flow.signed_packet_sizes),
            "summary": {
                "absolute_bytes": sum(abs(value) for value in flow.signed_packet_sizes),
                "duration_seconds": round(max(0.0, flow.ended_at - flow.started_at), 6),
                "max_absolute_packet_size": max(abs(value) for value in flow.signed_packet_sizes),
            },
        },
    }


def build_evidence_snapshot(
    alert: dict[str, Any],
    *,
    zeek: dict[str, Any],
    suricata: dict[str, Any],
    window_start: str,
    window_end: str,
) -> dict[str, Any]:
    event_id = sha256(f"{alert['event_id']}|evidence_snapshot|1".encode("utf-8")).hexdigest()
    return {
        "schema_version": 1,
        "event_type": "evidence_snapshot",
        "event_id": event_id,
        "sensor_id": alert["sensor_id"],
        "observed_at": alert["observed_at"],
        "alert_event_id": alert["event_id"],
        "window": {"start": window_start, "end": window_end},
        "flow": alert["flow"],
        "evidence": {
            "zeek": _sanitize_evidence(zeek),
            "suricata": _sanitize_evidence(suricata),
            "summary": {
                "zeek_events": len(zeek.get("events", [])),
                "suricata_alerts": len(suricata.get("alerts", [])),
            },
        },
    }


def _sanitize_evidence(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _sanitize_evidence(nested)
            for key, nested in value.items()
            if key.lower() not in SENSITIVE_EVIDENCE_FIELDS
        }
    if isinstance(value, list):
        return [_sanitize_evidence(nested) for nested in value]
    return value


def build_sensor_heartbeat(
    *,
    sensor_id: str,
    model_id: str,
    model_sha256: str,
    observed_at: datetime,
    last_capture_at: str | None,
    active_flows: int,
    capture_backlog: int,
    capture_received_packets: int | None,
    capture_dropped_packets: int | None,
    capture_drop_status: str,
) -> dict[str, Any]:
    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=timezone.utc)
    observed_text = observed_at.astimezone(timezone.utc).isoformat()
    identity = f"{sensor_id}|sensor_heartbeat|{observed_text}"
    drop_rate = None
    if capture_received_packets and capture_dropped_packets is not None:
        drop_rate = capture_dropped_packets / capture_received_packets
    return {
        "schema_version": 1,
        "event_type": "sensor_heartbeat",
        "event_id": sha256(identity.encode("utf-8")).hexdigest(),
        "sensor_id": sensor_id,
        "observed_at": observed_text,
        "model_id": model_id,
        "model_sha256": model_sha256,
        "last_capture_at": last_capture_at,
        "active_flows": int(active_flows),
        "capture_backlog": int(capture_backlog),
        "capture_received_packets": capture_received_packets,
        "capture_dropped_packets": capture_dropped_packets,
        "capture_drop_rate": drop_rate,
        "capture_drop_status": capture_drop_status,
    }


def _risk_level(probability: float) -> str:
    if probability >= 0.9:
        return "high"
    if probability >= 0.7:
        return "medium"
    if probability >= 0.5:
        return "low"
    return "informational"
