from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Protocol

from mineshark.sensor.capture import read_capture
from mineshark.sensor.config import SensorConfig
from mineshark.sensor.events import build_ai_alert, build_evidence_snapshot, build_sensor_heartbeat
from mineshark.sensor.flow import CompletedFlow, FlowAssembler
from mineshark.sensor.inference import TorchTransformerScorer
from mineshark.sensor.state import SensorStateStore
from mineshark.sensors.logs import query_suricata_alerts, query_zeek_context


class FlowScorer(Protocol):
    def validate(self) -> None: ...

    def score(self, flow: CompletedFlow) -> float: ...


class JsonlEventWriter:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def write(self, event: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        with self.path.open("a", encoding="utf-8", buffering=1) as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())


class SensorRuntime:
    def __init__(self, config: SensorConfig, *, scorer: FlowScorer | None = None):
        if config.model_manifest is None:
            raise ValueError("sensor runtime requires a verified model manifest")
        self.config = config
        self.manifest = config.model_manifest
        self.state = SensorStateStore(config.output.state_path)
        profile = self.manifest.feature_profile
        self.assembler = FlowAssembler(
            max_packets=profile.capture_packets,
            min_packets=profile.min_packets,
            idle_timeout=config.flow.idle_timeout_seconds,
            active_timeout=config.flow.active_timeout_seconds,
        )
        self.assembler.restore(self.state.load_active_flows())
        self.scorer = scorer or TorchTransformerScorer(self.manifest, config.model.checkpoint_path)
        self.writer = JsonlEventWriter(config.output.events_path)
        self.last_capture_at = self.state.get_metadata("last_capture_at")
        self.total_flows_inferred = int(self.state.get_metadata("total_flows_inferred", 0))
        self.total_alerts_emitted = int(self.state.get_metadata("total_alerts_emitted", 0))
        self.capture_received_packets = self.state.get_metadata("capture_received_packets")
        self.capture_dropped_packets = self.state.get_metadata("capture_dropped_packets")
        self.capture_drop_status = str(self.state.get_metadata("capture_drop_status", "unknown"))
        self._drain_outbox()

    def validate_model(self) -> None:
        self.scorer.validate()

    def capture_processed(self, path: str | Path) -> bool:
        capture_path = Path(path)
        return capture_path.is_file() and self.state.capture_processed(capture_signature(capture_path))

    def process_capture(self, path: str | Path, *, finalize: bool = False) -> dict[str, Any]:
        capture_path = Path(path)
        signature = capture_signature(capture_path)
        if self.state.capture_processed(signature):
            return {
                "capture": str(capture_path),
                "signature": signature,
                "skipped_already_processed": True,
                "flows_inferred": 0,
                "alerts_emitted": 0,
                "active_flows": self.assembler.active_count,
            }

        capture = read_capture(capture_path)
        completed: list[CompletedFlow] = []
        for packet in capture.packets:
            completed.extend(self.assembler.expire(packet.timestamp))
            completed.extend(self.assembler.add(packet))
        if finalize:
            completed.extend(self.assembler.flush_all("replay_end"))

        flows_inferred, alerts_emitted = self._infer_completed(completed)

        self.state.commit_capture(
            signature,
            packet_count=capture.stats.total_packets,
            active_flows=self.assembler.snapshot(),
        )
        if capture.stats.last_timestamp is not None:
            self.last_capture_at = datetime.fromtimestamp(
                capture.stats.last_timestamp,
                tz=timezone.utc,
            ).isoformat()
        self.capture_received_packets = capture.stats.interface_received_packets
        self.capture_dropped_packets = capture.stats.interface_dropped_packets
        self.capture_drop_status = capture.stats.drop_status
        self.total_flows_inferred += flows_inferred
        self.total_alerts_emitted += alerts_emitted
        self.state.set_metadata("last_capture_at", self.last_capture_at)
        self.state.set_metadata("total_flows_inferred", self.total_flows_inferred)
        self.state.set_metadata("total_alerts_emitted", self.total_alerts_emitted)
        self.state.set_metadata("capture_received_packets", self.capture_received_packets)
        self.state.set_metadata("capture_dropped_packets", self.capture_dropped_packets)
        self.state.set_metadata("capture_drop_status", self.capture_drop_status)
        self._drain_outbox()
        self._write_status(capture_backlog=0)
        return {
            "capture": str(capture_path),
            "signature": signature,
            "skipped_already_processed": False,
            "packets_total": capture.stats.total_packets,
            "tcp_packets": capture.stats.tcp_packets,
            "skipped_packets": capture.stats.skipped_packets,
            "flows_inferred": flows_inferred,
            "alerts_emitted": alerts_emitted,
            "active_flows": self.assembler.active_count,
        }

    def expire_flows(self, *, now: float | None = None) -> dict[str, int]:
        timestamp = float(now if now is not None else datetime.now(timezone.utc).timestamp())
        completed = self.assembler.expire(timestamp)
        flows_inferred, alerts_emitted = self._infer_completed(completed)
        self.state.save_active_flows(self.assembler.snapshot())
        self.total_flows_inferred += flows_inferred
        self.total_alerts_emitted += alerts_emitted
        self.state.set_metadata("total_flows_inferred", self.total_flows_inferred)
        self.state.set_metadata("total_alerts_emitted", self.total_alerts_emitted)
        self._drain_outbox()
        self._write_status(capture_backlog=0)
        return {
            "flows_inferred": flows_inferred,
            "alerts_emitted": alerts_emitted,
            "active_flows": self.assembler.active_count,
        }

    def emit_heartbeat(
        self,
        *,
        observed_at: datetime | None = None,
        capture_backlog: int = 0,
    ) -> dict[str, Any]:
        event = build_sensor_heartbeat(
            sensor_id=self.config.sensor_id,
            model_id=self.manifest.model_id,
            model_sha256=self.manifest.checkpoint_sha256,
            observed_at=observed_at or datetime.now(timezone.utc),
            last_capture_at=self.last_capture_at,
            active_flows=self.assembler.active_count,
            capture_backlog=capture_backlog,
            capture_received_packets=self.capture_received_packets,
            capture_dropped_packets=self.capture_dropped_packets,
            capture_drop_status=self.capture_drop_status,
        )
        self.writer.write(event)
        self._write_status(capture_backlog=capture_backlog, observed_at=event["observed_at"])
        return event

    def _queue_alert_and_evidence(self, flow: CompletedFlow, probability: float) -> bool:
        observed_at = datetime.fromtimestamp(flow.ended_at, tz=timezone.utc)
        alert = build_ai_alert(
            flow,
            sensor_id=self.config.sensor_id,
            model_id=self.manifest.model_id,
            model_sha256=self.manifest.checkpoint_sha256,
            threshold=self.config.model.threshold,
            malware_probability=probability,
            observed_at=observed_at,
        )
        was_new = self.state.record_alert_once(alert)
        if not was_new:
            return False

        window_start = datetime.fromtimestamp(flow.started_at, tz=timezone.utc) - timedelta(seconds=30)
        window_end = observed_at + timedelta(seconds=30)
        try:
            zeek = query_zeek_context(
                self.config.evidence.zeek_log_dir,
                ip=flow.src_ip,
                start_time=window_start.isoformat(),
                end_time=window_end.isoformat(),
                limit=50,
            )
        except OSError as exc:
            zeek = {"source_file": str(self.config.evidence.zeek_log_dir), "events": [], "error": str(exc)}
        try:
            suricata = query_suricata_alerts(
                self.config.evidence.suricata_eve_path,
                ip=flow.src_ip,
                start_time=window_start.isoformat(),
                end_time=window_end.isoformat(),
                limit=50,
            )
        except OSError as exc:
            suricata = {
                "source_file": str(self.config.evidence.suricata_eve_path),
                "alerts": [],
                "error": str(exc),
            }
        evidence = build_evidence_snapshot(
            alert,
            zeek=zeek,
            suricata=suricata,
            window_start=window_start.isoformat(),
            window_end=window_end.isoformat(),
        )
        self.state.record_alert_once(evidence)
        return True

    def _infer_completed(self, completed: list[CompletedFlow]) -> tuple[int, int]:
        flows_inferred = 0
        alerts_emitted = 0
        for flow in completed:
            probability = float(self.scorer.score(flow))
            flows_inferred += 1
            if probability >= self.config.model.threshold and self._queue_alert_and_evidence(flow, probability):
                alerts_emitted += 1
        return flows_inferred, alerts_emitted

    def _drain_outbox(self) -> None:
        for event in self.state.pending_events():
            self.writer.write(event)
            self.state.mark_event_emitted(str(event["event_id"]))

    def _write_status(self, *, capture_backlog: int, observed_at: str | None = None) -> None:
        drop_rate = None
        if self.capture_received_packets and self.capture_dropped_packets is not None:
            drop_rate = self.capture_dropped_packets / self.capture_received_packets
        status = {
            "schema_version": 1,
            "sensor_id": self.config.sensor_id,
            "observed_at": observed_at or datetime.now(timezone.utc).isoformat(),
            "model_id": self.manifest.model_id,
            "model_sha256": self.manifest.checkpoint_sha256,
            "last_capture_at": self.last_capture_at,
            "active_flows": self.assembler.active_count,
            "capture_backlog": int(capture_backlog),
            "capture_received_packets": self.capture_received_packets,
            "capture_dropped_packets": self.capture_dropped_packets,
            "capture_drop_rate": drop_rate,
            "capture_drop_status": self.capture_drop_status,
            "total_flows_inferred": self.total_flows_inferred,
            "total_alerts_emitted": self.total_alerts_emitted,
        }
        target = self.config.output.status_path
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".tmp")
        temporary.write_text(
            json.dumps(status, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
            encoding="utf-8",
        )
        os.replace(temporary, target)


def capture_signature(path: str | Path) -> str:
    digest = sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
