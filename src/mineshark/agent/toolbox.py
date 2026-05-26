from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from mineshark.config import RuntimeConfig, resolve_project_path
from mineshark.integrations.wazuh import WazuhServerClient, query_alerts_with_fallback
from mineshark.rag.embeddings import QwenEmbeddingClient
from mineshark.rag.store import FaissKnowledgeStore
from mineshark.sensors.ai_alerts import query_mineshark_ai_alerts as read_mineshark_ai_alerts
from mineshark.sensors.logs import query_suricata_alerts, query_zeek_context


def _safe_limit(value: int, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except Exception:
        return default
    return max(1, min(parsed, maximum))


def _trim_jsonable(payload: Any, max_chars: int = 6000) -> Any:
    text = json.dumps(payload, ensure_ascii=False, default=str)
    if len(text) <= max_chars:
        return payload
    return {"truncated": True, "preview": text[:max_chars]}


class AgentToolbox:
    def __init__(
        self,
        config: RuntimeConfig,
        checkpoint: Optional[str] = None,
        log_file: Optional[str] = None,
        threshold: float = 0.5,
        max_events: int = 5,
        top_k: int = 4,
    ):
        self.config = config
        self.checkpoint = checkpoint
        self.log_file = log_file
        self.threshold = threshold
        self.max_events = max_events
        self.top_k = top_k
        self.trace: List[Dict[str, Any]] = []
        self._rag_store: Optional[FaissKnowledgeStore] = None

    def _record(self, name: str, arguments: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
        self.trace.append(
            {
                "tool": name,
                "arguments": arguments,
                "result": _trim_jsonable(result),
            }
        )
        return result

    def run_traffic_model(
        self,
        log_file: Optional[str] = None,
        threshold: Optional[float] = None,
        max_events: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Run MineShark Transformer inference on a MineShark/Zeek-style traffic log."""
        target_log = log_file or self.log_file
        if not target_log:
            return self._record(
                "run_traffic_model",
                {"log_file": target_log},
                {"error": "No log_file was provided for Transformer inference.", "events": []},
            )
        if not self.checkpoint:
            return self._record(
                "run_traffic_model",
                {"log_file": target_log},
                {"error": "No checkpoint was provided for Transformer inference.", "events": []},
            )

        checkpoint_path = resolve_project_path(self.checkpoint)
        log_path = resolve_project_path(target_log)
        selected_threshold = float(self.threshold if threshold is None else threshold)
        selected_max_events = _safe_limit(max_events or self.max_events, self.max_events, 50)

        try:
            import torch

            from mineshark.reporting.agent_audit import (
                infer_events,
                load_model,
                parse_mineshark_events,
                risk_counts,
            )

            device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            model, model_config = load_model(checkpoint_path, device)
            raw_events = parse_mineshark_events(
                log_file=log_path,
                max_len=int(model_config.get("max_len", 128)),
                min_packets=int(model_config.get("min_packets", 3)),
                max_pkt_size=int(model_config.get("max_pkt_size", 2000)),
                max_iat=float(model_config.get("max_iat", 10.0)),
            )
            scored_events = infer_events(model, raw_events, device=device, batch_size=128)
            candidates = [
                event for event in scored_events if event["malware_probability"] >= selected_threshold
            ]
            candidates.sort(key=lambda item: item["malware_probability"], reverse=True)
            selected = candidates[:selected_max_events]
            result = {
                "source_file": str(log_path),
                "checkpoint": str(checkpoint_path),
                "threshold": selected_threshold,
                "total_valid_connections": len(scored_events),
                "connections_above_threshold": len(candidates),
                "reported_events": len(selected),
                "risk_counts": risk_counts(selected),
                "events": selected,
                "error": None,
            }
        except Exception as exc:
            result = {"source_file": str(log_path), "events": [], "error": str(exc)}
        return self._record(
            "run_traffic_model",
            {"log_file": target_log, "threshold": selected_threshold, "max_events": selected_max_events},
            result,
        )

    def query_mineshark_ai_alerts(
        self,
        ip: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        min_probability: Optional[float] = None,
        limit: int = 20,
    ) -> Dict[str, Any]:
        """Read real-time MineShark AI alerts from /var/log/ai_alerts.json."""
        safe_limit = _safe_limit(limit, 20, 100)
        selected_min_probability = self.threshold if min_probability is None else float(min_probability)
        result = read_mineshark_ai_alerts(
            self.config.mineshark_ai_alerts_path,
            ip=ip,
            start_time=start_time,
            end_time=end_time,
            min_probability=selected_min_probability,
            limit=safe_limit,
        )
        return self._record(
            "query_mineshark_ai_alerts",
            {
                "ip": ip,
                "start_time": start_time,
                "end_time": end_time,
                "min_probability": selected_min_probability,
                "limit": safe_limit,
            },
            result,
        )

    def query_wazuh_alerts(
        self,
        ip: Optional[str] = None,
        text: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 20,
    ) -> Dict[str, Any]:
        """Query Wazuh alerts from the Indexer API, falling back to local alerts.json."""
        safe_limit = _safe_limit(limit, 20, 100)
        result = query_alerts_with_fallback(
            self.config,
            ip=ip,
            text=text,
            start_time=start_time,
            end_time=end_time,
            limit=safe_limit,
        )
        return self._record(
            "query_wazuh_alerts",
            {"ip": ip, "text": text, "start_time": start_time, "end_time": end_time, "limit": safe_limit},
            result,
        )

    def query_wazuh_agents(self, limit: int = 20) -> Dict[str, Any]:
        """Query Wazuh manager status and agent list from the Wazuh Server API."""
        safe_limit = _safe_limit(limit, 20, 100)
        try:
            client = WazuhServerClient(self.config)
            result = {
                "manager_status": client.manager_status(),
                "agents": client.agents(limit=safe_limit),
                "error": None,
            }
        except Exception as exc:
            result = {"manager_status": None, "agents": None, "error": str(exc)}
        return self._record("query_wazuh_agents", {"limit": safe_limit}, result)

    def query_zeek_context(
        self,
        ip: Optional[str] = None,
        uid: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Query Zeek conn.log context by IP, UID, and optional time range."""
        safe_limit = _safe_limit(limit, 50, 200)
        result = query_zeek_context(
            self.config.zeek_log_dir,
            ip=ip,
            uid=uid,
            start_time=start_time,
            end_time=end_time,
            limit=safe_limit,
        )
        return self._record(
            "query_zeek_context",
            {"ip": ip, "uid": uid, "start_time": start_time, "end_time": end_time, "limit": safe_limit},
            result,
        )

    def query_suricata_alerts(
        self,
        ip: Optional[str] = None,
        signature: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Query Suricata eve.json alerts by IP, signature, and optional time range."""
        safe_limit = _safe_limit(limit, 50, 200)
        result = query_suricata_alerts(
            self.config.suricata_eve_path,
            ip=ip,
            signature=signature,
            start_time=start_time,
            end_time=end_time,
            limit=safe_limit,
        )
        return self._record(
            "query_suricata_alerts",
            {
                "ip": ip,
                "signature": signature,
                "start_time": start_time,
                "end_time": end_time,
                "limit": safe_limit,
            },
            result,
        )

    def retrieve_security_knowledge(self, query: str, top_k: Optional[int] = None) -> Dict[str, Any]:
        """Retrieve security playbook knowledge from the local FAISS RAG index."""
        selected_top_k = _safe_limit(top_k or self.top_k, self.top_k, 20)
        try:
            if self._rag_store is None:
                embedding_client = QwenEmbeddingClient(
                    api_key=self.config.dashscope_api_key,
                    base_url=self.config.dashscope_base_url,
                    model=self.config.dashscope_embedding_model,
                )
                self._rag_store = FaissKnowledgeStore(self.config.rag_index_dir, embedding_client)
            matches = self._rag_store.search(query, top_k=selected_top_k)
            result = {"matches": matches, "error": None}
        except Exception as exc:
            result = {"matches": [], "error": str(exc)}
        return self._record(
            "retrieve_security_knowledge",
            {"query": query, "top_k": selected_top_k},
            result,
        )


def build_langchain_tools(toolbox: AgentToolbox, include_model_tool: bool = False):
    try:
        from langchain_core.tools import StructuredTool
    except Exception as exc:
        raise RuntimeError("langchain-core is required to build Agent tools.") from exc

    tools = [
        StructuredTool.from_function(
            func=toolbox.query_mineshark_ai_alerts,
            name="query_mineshark_ai_alerts",
            description=(
                "Read real-time MineShark AI alerts from /var/log/ai_alerts.json. "
                "Use this as the primary model evidence source."
            ),
        ),
    ]
    if include_model_tool:
        tools.append(
            StructuredTool.from_function(
                func=toolbox.run_traffic_model,
                name="run_traffic_model",
                description=(
                    "Optional fallback: run MineShark Transformer inference on a traffic log "
                    "when live AI alerts are unavailable or explicit rerun was requested."
                ),
            )
        )
    tools.extend(
        [
            StructuredTool.from_function(
                func=toolbox.query_wazuh_alerts,
                name="query_wazuh_alerts",
                description="Query Wazuh alerts by IP, text, and time range; falls back to local alerts.json.",
            ),
            StructuredTool.from_function(
                func=toolbox.query_wazuh_agents,
                name="query_wazuh_agents",
                description="Query Wazuh manager status and agent list.",
            ),
            StructuredTool.from_function(
                func=toolbox.query_zeek_context,
                name="query_zeek_context",
                description="Query Zeek conn.log context by IP, UID, and optional time range.",
            ),
            StructuredTool.from_function(
                func=toolbox.query_suricata_alerts,
                name="query_suricata_alerts",
                description="Query Suricata eve.json alerts by IP, signature, and optional time range.",
            ),
            StructuredTool.from_function(
                func=toolbox.retrieve_security_knowledge,
                name="retrieve_security_knowledge",
                description="Retrieve relevant security playbook knowledge from the FAISS RAG index.",
            ),
        ]
    )
    return tools
