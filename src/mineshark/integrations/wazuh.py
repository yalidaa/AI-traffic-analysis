from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import requests

from mineshark.config import RuntimeConfig


def _url_join(base_url: str, path: str) -> str:
    return base_url.rstrip("/") + "/" + path.lstrip("/")


def _contains_value(record: Any, needle: str) -> bool:
    if not needle:
        return True
    if isinstance(record, dict):
        return any(_contains_value(value, needle) for value in record.values())
    if isinstance(record, list):
        return any(_contains_value(value, needle) for value in record)
    return str(record) == needle


def _contains_text(record: Any, text: str) -> bool:
    if not text:
        return True
    return text.lower() in json.dumps(record, ensure_ascii=False).lower()


class WazuhServerClient:
    def __init__(self, config: RuntimeConfig):
        self.config = config
        self.session = requests.Session()
        self._token: Optional[str] = None

    def authenticate(self) -> str:
        response = self.session.get(
            _url_join(self.config.wazuh_base_url, "/security/user/authenticate"),
            auth=(self.config.wazuh_username, self.config.wazuh_password),
            verify=self.config.wazuh_verify_ssl,
            timeout=self.config.wazuh_timeout,
        )
        response.raise_for_status()
        payload = response.json()
        token = payload.get("data", {}).get("token") or payload.get("token")
        if not token:
            raise ValueError("Wazuh Server API authentication response did not include a token.")
        self._token = token
        return token

    def _headers(self) -> Dict[str, str]:
        if not self._token:
            self.authenticate()
        return {"Authorization": f"Bearer {self._token}"}

    def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        response = self.session.get(
            _url_join(self.config.wazuh_base_url, path),
            headers=self._headers(),
            params=params,
            verify=self.config.wazuh_verify_ssl,
            timeout=self.config.wazuh_timeout,
        )
        response.raise_for_status()
        return response.json()

    def manager_status(self) -> Dict[str, Any]:
        return self.get("/manager/status")

    def agents(self, limit: int = 20, offset: int = 0) -> Dict[str, Any]:
        return self.get("/agents", params={"limit": limit, "offset": offset})


class WazuhIndexerClient:
    def __init__(self, config: RuntimeConfig):
        self.config = config
        self.session = requests.Session()

    def search_alerts(
        self,
        ip: Optional[str] = None,
        text: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        filters: List[Dict[str, Any]] = []
        must: List[Dict[str, Any]] = []
        should: List[Dict[str, Any]] = []

        if start_time or end_time:
            range_body: Dict[str, Any] = {}
            if start_time:
                range_body["gte"] = start_time
            if end_time:
                range_body["lte"] = end_time
            filters.append({"range": {"@timestamp": range_body}})

        if ip:
            ip_fields = [
                "data.srcip",
                "data.dstip",
                "source.ip",
                "destination.ip",
                "agent.ip",
                "srcip",
                "dstip",
            ]
            should.extend({"match_phrase": {field: ip}} for field in ip_fields)

        if text:
            must.append({"query_string": {"query": text}})

        bool_query: Dict[str, Any] = {}
        if filters:
            bool_query["filter"] = filters
        if must:
            bool_query["must"] = must
        if should:
            bool_query["should"] = should
            bool_query["minimum_should_match"] = 1

        query = {"bool": bool_query} if bool_query else {"match_all": {}}
        body = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "query": query,
        }

        response = self.session.post(
            _url_join(self.config.wazuh_indexer_url, f"/{self.config.wazuh_index_pattern}/_search"),
            auth=(self.config.wazuh_indexer_username, self.config.wazuh_indexer_password),
            json=body,
            verify=self.config.wazuh_verify_ssl,
            timeout=self.config.wazuh_timeout,
        )
        response.raise_for_status()
        payload = response.json()
        hits = payload.get("hits", {}).get("hits", [])
        return [hit.get("_source", hit) for hit in hits]


def iter_local_alerts(alerts_path: Path) -> Iterable[Dict[str, Any]]:
    if not alerts_path.exists():
        return
    with alerts_path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def read_local_alerts(
    alerts_path: Path,
    ip: Optional[str] = None,
    text: Optional[str] = None,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    matches = []
    for alert in iter_local_alerts(alerts_path):
        if ip and not _contains_value(alert, ip):
            continue
        if text and not _contains_text(alert, text):
            continue
        matches.append(alert)
        if len(matches) >= limit:
            break
    return matches


def query_alerts_with_fallback(
    config: RuntimeConfig,
    ip: Optional[str] = None,
    text: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    try:
        alerts = WazuhIndexerClient(config).search_alerts(
            ip=ip,
            text=text,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
        )
        return {"source": "wazuh_indexer_api", "alerts": alerts, "error": None}
    except Exception as exc:
        local_alerts = read_local_alerts(config.wazuh_alerts_path, ip=ip, text=text, limit=limit)
        return {
            "source": "local_alerts_json",
            "alerts": local_alerts,
            "error": f"Indexer query failed; used local alerts fallback: {exc}",
        }
