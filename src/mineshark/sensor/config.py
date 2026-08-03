from __future__ import annotations

import re

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 compatibility for Ubuntu 22.04.
    import tomli as tomllib
from dataclasses import dataclass
from pathlib import Path

from mineshark.sensor.manifest import ModelManifest


@dataclass(frozen=True)
class CaptureConfig:
    dumpcap_path: str
    spool_dir: Path
    snaplen: int
    rotate_seconds: int
    ring_files: int


@dataclass(frozen=True)
class FlowConfig:
    idle_timeout_seconds: float
    active_timeout_seconds: float


@dataclass(frozen=True)
class ModelConfig:
    checkpoint_path: Path
    manifest_path: Path
    threshold: float


@dataclass(frozen=True)
class OutputConfig:
    events_path: Path
    status_path: Path
    state_path: Path


@dataclass(frozen=True)
class EvidenceConfig:
    zeek_log_dir: Path
    suricata_eve_path: Path


@dataclass(frozen=True)
class SensorConfig:
    sensor_id: str
    interface: str
    bpf: str
    capture: CaptureConfig
    flow: FlowConfig
    model: ModelConfig
    output: OutputConfig
    evidence: EvidenceConfig
    poll_seconds: float
    model_manifest: ModelManifest | None

    @classmethod
    def load(cls, path: str | Path, *, verify_model: bool = True) -> "SensorConfig":
        config_path = Path(path)
        try:
            with config_path.open("rb") as handle:
                payload = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ValueError(f"unable to read sensor config: {exc}") from exc

        sensor_id = str(payload.get("sensor_id", "")).strip()
        interface = str(payload.get("interface", "")).strip()
        bpf = str(payload.get("bpf", "tcp")).strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", sensor_id):
            raise ValueError("sensor_id must contain only letters, digits, dot, underscore, or hyphen")
        if not interface or len(interface) > 64 or any(character.isspace() for character in interface):
            raise ValueError("interface must be a non-empty interface name without whitespace")
        if not bpf:
            raise ValueError("bpf must not be empty")

        capture_payload = payload.get("capture") or {}
        capture = CaptureConfig(
            dumpcap_path=str(capture_payload.get("dumpcap_path", "/usr/bin/dumpcap")),
            spool_dir=Path(capture_payload.get("spool_dir", "/var/spool/mineshark")),
            snaplen=int(capture_payload.get("snaplen", 128)),
            rotate_seconds=int(capture_payload.get("rotate_seconds", 5)),
            ring_files=int(capture_payload.get("ring_files", 60)),
        )
        if capture.snaplen != 128:
            raise ValueError("capture snaplen must be 128")
        if capture.rotate_seconds != 5:
            raise ValueError("capture rotate_seconds must be 5")
        if capture.ring_files != 60:
            raise ValueError("capture ring_files must be 60")

        flow_payload = payload.get("flow") or {}
        flow = FlowConfig(
            idle_timeout_seconds=float(flow_payload.get("idle_timeout_seconds", 30.0)),
            active_timeout_seconds=float(flow_payload.get("active_timeout_seconds", 120.0)),
        )
        if flow.idle_timeout_seconds <= 0 or flow.active_timeout_seconds <= 0:
            raise ValueError("flow timeouts must be positive")
        if flow.idle_timeout_seconds >= flow.active_timeout_seconds:
            raise ValueError("idle timeout must be shorter than active timeout")

        model_payload = payload.get("model") or {}
        model = ModelConfig(
            checkpoint_path=Path(model_payload.get("checkpoint_path", "/opt/mineshark/models/model.pt")),
            manifest_path=Path(model_payload.get("manifest_path", "/opt/mineshark/models/manifest.json")),
            threshold=float(model_payload.get("threshold", 0.5)),
        )
        if not 0.0 <= model.threshold <= 1.0:
            raise ValueError("model threshold must be between 0 and 1")

        output_payload = payload.get("output") or {}
        output = OutputConfig(
            events_path=Path(output_payload.get("events_path", "/var/log/mineshark/events.jsonl")),
            status_path=Path(output_payload.get("status_path", "/var/lib/mineshark/status.json")),
            state_path=Path(output_payload.get("state_path", "/var/lib/mineshark/sensor.sqlite3")),
        )
        evidence_payload = payload.get("evidence") or {}
        evidence = EvidenceConfig(
            zeek_log_dir=Path(evidence_payload.get("zeek_log_dir", "/opt/zeek/logs/current")),
            suricata_eve_path=Path(evidence_payload.get("suricata_eve_path", "/var/log/suricata/eve.json")),
        )
        poll_seconds = float(payload.get("poll_seconds", 1.0))
        if poll_seconds <= 0:
            raise ValueError("poll_seconds must be positive")

        manifest = None
        if verify_model:
            manifest = ModelManifest.load(model.manifest_path, model.checkpoint_path)
            if manifest.feature_profile.name != "legacy-zeek-v1":
                raise ValueError("unsupported model feature profile")
            if abs(manifest.threshold - model.threshold) > 1e-12:
                raise ValueError("configured threshold does not match the verified model manifest")

        return cls(
            sensor_id=sensor_id,
            interface=interface,
            bpf=bpf,
            capture=capture,
            flow=flow,
            model=model,
            output=output,
            evidence=evidence,
            poll_seconds=poll_seconds,
            model_manifest=manifest,
        )
