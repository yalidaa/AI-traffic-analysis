from __future__ import annotations

from typing import Any, Dict, List


def _contains_any(text: str, needles: List[str]) -> bool:
    lowered = text.lower()
    return any(needle.lower() in lowered for needle in needles)


def evaluate_report_quality(markdown: str, evidence_bundle: Dict[str, Any]) -> Dict[str, Any]:
    checks = [
        {
            "name": "ai_alert_summary",
            "passed": bool(evidence_bundle.get("selected_alerts"))
            and _contains_any(markdown, ["MineShark", "AI 告警", "模型"]),
            "detail": "Report should include selected MineShark AI alert evidence.",
        },
        {
            "name": "wazuh_evidence",
            "passed": bool(evidence_bundle.get("wazuh_evidence", {}).get("alerts"))
            and _contains_any(markdown, ["Wazuh", "告警"]),
            "detail": "Report should mention Wazuh evidence when it exists.",
        },
        {
            "name": "network_context",
            "passed": (
                bool(evidence_bundle.get("zeek_context", {}).get("events"))
                or bool(evidence_bundle.get("suricata_alerts", {}).get("alerts"))
            )
            and _contains_any(markdown, ["Zeek", "Suricata", "连接", "上下文"]),
            "detail": "Report should mention Zeek or Suricata context when available.",
        },
        {
            "name": "rag_basis",
            "passed": bool(evidence_bundle.get("rag_matches", {}).get("matches"))
            and _contains_any(markdown, ["RAG", "知识", "playbook", "依据"]),
            "detail": "Report should include RAG knowledge basis when matches exist.",
        },
        {
            "name": "limitations",
            "passed": _contains_any(markdown, ["误报", "局限", "风险线索", "不能直接", "人工复核"]),
            "detail": "Report should explain false-positive boundaries and manual review.",
        },
    ]
    status = "complete" if all(item["passed"] for item in checks) else "incomplete"
    return {
        "status": status,
        "checks": checks,
        "missing": [item["name"] for item in checks if not item["passed"]],
    }
