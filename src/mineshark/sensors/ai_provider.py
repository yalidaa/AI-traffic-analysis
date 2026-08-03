from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

from mineshark.config import RuntimeConfig
from mineshark.integrations.wazuh import WazuhIndexerClient
from mineshark.sensors.ai_alerts import query_mineshark_ai_alerts


def query_configured_ai_alerts(
    config: RuntimeConfig,
    *,
    ip: str | None = None,
    uid: str | None = None,
    alert_id: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    min_probability: float | None = 0.5,
    limit: int = 20,
) -> dict[str, Any]:
    if config.mineshark_ai_alert_source == "local":
        result = query_mineshark_ai_alerts(
            config.mineshark_ai_alerts_path,
            ip=ip,
            uid=uid,
            alert_id=alert_id,
            start_time=start_time,
            end_time=end_time,
            min_probability=min_probability,
            limit=limit,
        )
        result["provider"] = "local"
        result["quarantined"] = 0
        return result
    if not config.mineshark_allowed_sensor_ids:
        return _empty_result(config, "wazuh provider requires at least one allowed sensor id")
    try:
        records = WazuhIndexerClient(config).search_mineshark_events(
            event_type="ai_alert",
            sensor_ids=config.mineshark_allowed_sensor_ids,
            start_time=start_time,
            end_time=end_time,
            limit=max(limit * 4, 100),
        )
    except Exception as exc:
        return _empty_result(config, f"Wazuh AI alert query failed: {exc}")

    selected = []
    quarantined = 0
    duplicates = 0
    seen_event_ids: set[str] = set()
    for record in records:
        event = _extract_event(record)
        if not _event_allowed(event, config.mineshark_allowed_sensor_ids, "ai_alert"):
            quarantined += 1
            continue
        if not _contains_value(event, ip):
            continue
        if uid and str(_find_first(event, {"uid", "zeek_uid", "connection_uid", "flow_uid"})) != uid:
            continue
        if alert_id and str(_find_first(event, {"event_id", "alert_id", "id"})) != alert_id:
            continue
        probability = _float_value(_find_first(event, {"malware_probability", "probability", "risk_score"}))
        if min_probability is not None and probability is not None and probability < min_probability:
            continue
        event_id = str(event.get("event_id", ""))
        if event_id and event_id in seen_event_ids:
            duplicates += 1
            continue
        if event_id:
            seen_event_ids.add(event_id)
        item = dict(event)
        item["_mineshark_score"] = probability
        item["_mineshark_timestamp"] = _find_first(event, {"observed_at", "timestamp", "@timestamp"})
        item["_mineshark_alert_id"] = _find_first(event, {"event_id", "alert_id", "id"})
        if isinstance(record.get("rule"), dict):
            item["_wazuh_rule"] = record["rule"]
        selected.append(item)
        if len(selected) >= limit:
            break
    return {
        "provider": "wazuh",
        "source_file": f"wazuh://{config.wazuh_index_pattern}",
        "exists": True,
        "total_records": len(records),
        "invalid_lines": 0,
        "matched": len(selected),
        "alerts": selected,
        "empty": len(records) == 0,
        "quarantined": quarantined,
        "duplicates": duplicates,
        "error": None,
    }


def query_sensor_heartbeats(
    config: RuntimeConfig,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    if config.mineshark_ai_alert_source != "wazuh":
        return {"provider": config.mineshark_ai_alert_source, "sensors": [], "quarantined": 0, "error": None}
    allowed = config.mineshark_allowed_sensor_ids
    if not allowed:
        return {"provider": "wazuh", "sensors": [], "quarantined": 0, "error": "no allowed sensors configured"}
    try:
        records = WazuhIndexerClient(config).search_mineshark_events(
            event_type="sensor_heartbeat",
            sensor_ids=allowed,
            limit=max(100, len(allowed) * 10),
        )
    except Exception as exc:
        return {"provider": "wazuh", "sensors": [], "quarantined": 0, "error": str(exc)}

    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    latest: dict[str, dict[str, Any]] = {}
    quarantined = 0
    for record in records:
        event = _extract_event(record)
        if not _event_allowed(event, allowed, "sensor_heartbeat"):
            quarantined += 1
            continue
        sensor_id = str(event["sensor_id"])
        if sensor_id not in latest:
            latest[sensor_id] = event

    sensors = []
    for sensor_id in allowed:
        heartbeat = latest.get(sensor_id)
        if heartbeat is None:
            sensors.append({"sensor_id": sensor_id, "status": "missing", "heartbeat": None})
            continue
        observed_at = _parse_timestamp(heartbeat.get("observed_at"))
        age_seconds = None if observed_at is None else max(0.0, (current - observed_at).total_seconds())
        status = (
            "unknown"
            if age_seconds is None
            else "healthy"
            if age_seconds <= config.sensor_heartbeat_stale_seconds
            else "stale"
        )
        sensors.append(
            {
                "sensor_id": sensor_id,
                "status": status,
                "heartbeat_age_seconds": age_seconds,
                "heartbeat": heartbeat,
            }
        )
    return {"provider": "wazuh", "sensors": sensors, "quarantined": quarantined, "error": None}


def query_sensor_evidence_snapshots(
    config: RuntimeConfig,
    *,
    alert_event_id: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    if config.mineshark_ai_alert_source != "wazuh":
        return {"provider": config.mineshark_ai_alert_source, "snapshots": [], "quarantined": 0, "error": None}
    allowed = config.mineshark_allowed_sensor_ids
    if not allowed:
        return {"provider": "wazuh", "snapshots": [], "quarantined": 0, "error": "no allowed sensors configured"}
    try:
        records = WazuhIndexerClient(config).search_mineshark_events(
            event_type="evidence_snapshot",
            sensor_ids=allowed,
            start_time=start_time,
            end_time=end_time,
            limit=max(limit * 4, 100),
        )
    except Exception as exc:
        return {"provider": "wazuh", "snapshots": [], "quarantined": 0, "error": str(exc)}
    snapshots = []
    quarantined = 0
    for record in records:
        event = _extract_event(record)
        if not _event_allowed(event, allowed, "evidence_snapshot"):
            quarantined += 1
            continue
        if alert_event_id and str(event.get("alert_event_id", "")) != alert_event_id:
            continue
        snapshots.append(event)
        if len(snapshots) >= limit:
            break
    return {
        "provider": "wazuh",
        "snapshots": snapshots,
        "quarantined": quarantined,
        "error": None,
    }


def _empty_result(config: RuntimeConfig, error: str) -> dict[str, Any]:
    return {
        "provider": config.mineshark_ai_alert_source,
        "source_file": f"wazuh://{config.wazuh_index_pattern}",
        "exists": False,
        "total_records": 0,
        "invalid_lines": 0,
        "matched": 0,
        "alerts": [],
        "empty": True,
        "quarantined": 0,
        "duplicates": 0,
        "error": error,
    }


def _extract_event(record: dict[str, Any]) -> dict[str, Any]:
    candidates = [record, record.get("data"), (record.get("data") or {}).get("mineshark")]
    for candidate in candidates:
        if isinstance(candidate, dict) and "event_type" in candidate:
            return candidate
    return {}


def _event_allowed(event: dict[str, Any], allowed: tuple[str, ...], event_type: str) -> bool:
    try:
        schema_version = int(event.get("schema_version", 0))
    except (TypeError, ValueError):
        return False
    return schema_version == 1 and event.get("event_type") == event_type and str(event.get("sensor_id", "")) in allowed


def _iter_values(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        for nested in value.values():
            yield from _iter_values(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _iter_values(nested)
    else:
        yield value


def _contains_value(event: dict[str, Any], expected: str | None) -> bool:
    return expected is None or any(str(value) == expected for value in _iter_values(event))


def _find_first(value: Any, keys: set[str]) -> Any:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key in keys:
                return nested
        for nested in value.values():
            found = _find_first(nested, keys)
            if found is not None:
                return found
    elif isinstance(value, list):
        for nested in value:
            found = _find_first(nested, keys)
            if found is not None:
                return found
    return None


def _float_value(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
