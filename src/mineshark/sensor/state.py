from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterator


class SensorStateStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    event_id TEXT PRIMARY KEY,
                    event_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    emitted_at TEXT
                );
                CREATE TABLE IF NOT EXISTS processed_captures (
                    signature TEXT PRIMARY KEY,
                    packet_count INTEGER NOT NULL,
                    processed_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS active_flows (
                    flow_key TEXT PRIMARY KEY,
                    flow_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sensor_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def record_alert_once(self, event: dict[str, Any]) -> bool:
        event_id = str(event["event_id"])
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO alerts (event_id, event_json, created_at, emitted_at) VALUES (?, ?, ?, NULL)",
                (
                    event_id,
                    json.dumps(event, ensure_ascii=False, separators=(",", ":")),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            return cursor.rowcount == 1

    def pending_events(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT event_json FROM alerts WHERE emitted_at IS NULL ORDER BY created_at, event_id"
            ).fetchall()
        return [json.loads(payload) for (payload,) in rows]

    def mark_event_emitted(self, event_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE alerts SET emitted_at = ? WHERE event_id = ?",
                (datetime.now(timezone.utc).isoformat(), event_id),
            )

    def capture_processed(self, signature: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM processed_captures WHERE signature = ?",
                (signature,),
            ).fetchone()
        return row is not None

    def mark_capture_processed(self, signature: str, *, packet_count: int) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO processed_captures (signature, packet_count, processed_at)
                VALUES (?, ?, ?)
                """,
                (signature, int(packet_count), datetime.now(timezone.utc).isoformat()),
            )

    def save_active_flows(self, flows: list[dict[str, Any]]) -> None:
        rows = self._active_flow_rows(flows)
        with self._connect() as connection:
            connection.execute("DELETE FROM active_flows")
            connection.executemany(
                "INSERT INTO active_flows (flow_key, flow_json) VALUES (?, ?)",
                rows,
            )

    def commit_capture(
        self,
        signature: str,
        *,
        packet_count: int,
        active_flows: list[dict[str, Any]],
    ) -> None:
        rows = self._active_flow_rows(active_flows)
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM active_flows")
            connection.executemany(
                "INSERT INTO active_flows (flow_key, flow_json) VALUES (?, ?)",
                rows,
            )
            connection.execute(
                "INSERT OR REPLACE INTO processed_captures (signature, packet_count, processed_at) VALUES (?, ?, ?)",
                (signature, int(packet_count), now),
            )

    @staticmethod
    def _active_flow_rows(flows: list[dict[str, Any]]) -> list[tuple[str, str]]:
        rows = []
        for flow in flows:
            if flow.get("state_type") == "suppressed":
                key_payload = ["suppressed", flow["first_endpoint"], flow["second_endpoint"], flow["protocol"]]
            else:
                key_payload = [
                    "active",
                    flow["src_ip"],
                    int(flow["src_port"]),
                    flow["dst_ip"],
                    int(flow["dst_port"]),
                    flow["protocol"],
                ]
            flow_key = sha256(json.dumps(key_payload, separators=(",", ":")).encode("utf-8")).hexdigest()
            rows.append(
                (
                    flow_key,
                    json.dumps(flow, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
                )
            )
        return rows

    def load_active_flows(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT flow_json FROM active_flows ORDER BY flow_key").fetchall()
        flows = []
        for (payload,) in rows:
            try:
                flow = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise ValueError("invalid active flow state in SQLite") from exc
            if not isinstance(flow, dict):
                raise ValueError("invalid active flow state in SQLite")
            flows.append(flow)
        return flows

    def set_metadata(self, key: str, value: Any) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO sensor_metadata (key, value) VALUES (?, ?)",
                (key, json.dumps(value, ensure_ascii=False, separators=(",", ":"))),
            )

    def get_metadata(self, key: str, default: Any = None) -> Any:
        with self._connect() as connection:
            row = connection.execute("SELECT value FROM sensor_metadata WHERE key = ?", (key,)).fetchone()
        if row is None:
            return default
        return json.loads(row[0])
