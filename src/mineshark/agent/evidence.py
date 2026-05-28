from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional

from mineshark.agent.toolbox import AgentToolbox


ID_KEYS = {"uid", "zeek_uid", "connection_uid", "flow_uid", "_mineshark_uid"}
ALERT_ID_KEYS = {"alert_id", "id", "event_id", "rule_id", "alert_uid", "_mineshark_alert_id"}
SRC_IP_KEYS = {"src_ip", "srcip", "source.ip", "id.orig_h"}
DST_IP_KEYS = {"dst_ip", "dstip", "dest_ip", "destination.ip", "id.resp_h"}
TIME_KEYS = {"@timestamp", "timestamp", "ts", "time", "generated_at", "event_time", "_mineshark_timestamp"}


def _iter_items(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        for item in value.values():
            yield from _iter_items(item)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_items(item)
    else:
        yield value


def _find_first(record: Any, keys: set[str]) -> Optional[str]:
    if isinstance(record, dict):
        for key, value in record.items():
            if key in keys and value not in (None, ""):
                return str(value)
        for value in record.values():
            found = _find_first(value, keys)
            if found:
                return found
    elif isinstance(record, list):
        for value in record:
            found = _find_first(value, keys)
            if found:
                return found
    return None


def _first_ip(record: Dict[str, Any]) -> Optional[str]:
    return _find_first(record, SRC_IP_KEYS) or _find_first(record, DST_IP_KEYS)


def _compact_alert_for_query(alert: Dict[str, Any]) -> str:
    fields = {
        "uid": _find_first(alert, ID_KEYS),
        "alert_id": _find_first(alert, ALERT_ID_KEYS),
        "src_ip": _find_first(alert, SRC_IP_KEYS),
        "dst_ip": _find_first(alert, DST_IP_KEYS),
        "score": alert.get("_mineshark_score"),
        "prediction": alert.get("prediction") or alert.get("label") or alert.get("class"),
    }
    return json.dumps({key: value for key, value in fields.items() if value}, ensure_ascii=False)


def _append_error(errors: List[str], source: str, result: Dict[str, Any]) -> None:
    error = result.get("error")
    if error:
        errors.append(f"{source}: {error}")


def build_evidence_bundle(
    toolbox: AgentToolbox,
    *,
    alert_id: Optional[str] = None,
    uid: Optional[str] = None,
    ip: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    threshold: float = 0.5,
    max_events: int = 5,
    top_k: int = 4,
) -> Dict[str, Any]:
    ai_result = toolbox.query_mineshark_ai_alerts(
        ip=ip,
        uid=uid,
        alert_id=alert_id,
        start_time=start_time,
        end_time=end_time,
        min_probability=threshold,
        limit=max_events,
    )
    selected_alerts = list(ai_result.get("alerts", []))[:max_events]
    primary_alert = selected_alerts[0] if selected_alerts else {}

    selected_uid = uid or _find_first(primary_alert, ID_KEYS)
    selected_alert_id = alert_id or _find_first(primary_alert, ALERT_ID_KEYS)
    selected_ip = ip or _first_ip(primary_alert)
    selected_start = start_time or _find_first(primary_alert, TIME_KEYS)
    selected_end = end_time

    text_query = selected_alert_id or selected_uid
    wazuh_result = toolbox.query_wazuh_alerts(
        ip=selected_ip,
        text=text_query,
        start_time=selected_start,
        end_time=selected_end,
        limit=max(20, max_events),
    )
    zeek_result = toolbox.query_zeek_context(
        ip=selected_ip,
        uid=selected_uid,
        start_time=selected_start,
        end_time=selected_end,
        limit=50,
    )
    suricata_result = toolbox.query_suricata_alerts(
        ip=selected_ip,
        start_time=selected_start,
        end_time=selected_end,
        limit=50,
    )

    rag_query_parts = [
        "MineShark security triage",
        _compact_alert_for_query(primary_alert) if primary_alert else "",
        selected_uid or "",
        selected_alert_id or "",
        selected_ip or "",
    ]
    rag_result = toolbox.retrieve_security_knowledge(" ".join(part for part in rag_query_parts if part), top_k=top_k)

    errors: List[str] = []
    for source, result in (
        ("ai_alerts", ai_result),
        ("wazuh", wazuh_result),
        ("zeek", zeek_result),
        ("suricata", suricata_result),
        ("rag", rag_result),
    ):
        _append_error(errors, source, result)

    missing_sources = []
    if not selected_alerts:
        missing_sources.append("ai_alerts")
    if not wazuh_result.get("alerts"):
        missing_sources.append("wazuh")
    if not zeek_result.get("events"):
        missing_sources.append("zeek")
    if not suricata_result.get("alerts"):
        missing_sources.append("suricata")
    if not rag_result.get("matches"):
        missing_sources.append("rag")

    return {
        "selected_alerts": selected_alerts,
        "query_keys": {
            "alert_id": selected_alert_id,
            "uid": selected_uid,
            "ip": selected_ip,
            "start_time": selected_start,
            "end_time": selected_end,
            "threshold": threshold,
        },
        "wazuh_evidence": wazuh_result,
        "zeek_context": zeek_result,
        "suricata_alerts": suricata_result,
        "rag_matches": rag_result,
        "missing_sources": missing_sources,
        "errors": errors,
    }
