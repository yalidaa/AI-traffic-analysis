from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path


@dataclass(frozen=True)
class FeatureProfile:
    name: str
    max_len: int
    capture_packets: int
    min_packets: int
    max_pkt_size: int
    max_iat: float
    time_semantics: str
    packet_length_semantics: str
    direction_semantics: str


@dataclass(frozen=True)
class ModelArchitecture:
    embed_dim: int
    num_heads: int
    num_layers: int
    ff_dim: int
    dropout: float
    num_classes: int


@dataclass(frozen=True)
class ModelManifest:
    schema_version: int
    model_id: str
    checkpoint_sha256: str
    threshold: float
    architecture: ModelArchitecture
    feature_profile: FeatureProfile

    @classmethod
    def load(cls, manifest_path: str | Path, checkpoint_path: str | Path) -> "ModelManifest":
        manifest_file = Path(manifest_path)
        checkpoint_file = Path(checkpoint_path)
        payload = json.loads(manifest_file.read_text(encoding="utf-8"))
        if int(payload.get("schema_version", 0)) != 1:
            raise ValueError("unsupported model manifest schema")
        if not checkpoint_file.is_file():
            raise ValueError(f"checkpoint not found: {checkpoint_file}")

        expected_hash = str(payload.get("checkpoint_sha256", "")).lower()
        actual_hash = _sha256_file(checkpoint_file)
        if actual_hash != expected_hash:
            raise ValueError(f"checkpoint SHA-256 mismatch: expected {expected_hash}, got {actual_hash}")

        feature_payload = payload.get("feature_profile") or {}
        feature_profile = FeatureProfile(
            name=str(feature_payload["name"]),
            max_len=int(feature_payload["max_len"]),
            capture_packets=int(feature_payload["capture_packets"]),
            min_packets=int(feature_payload["min_packets"]),
            max_pkt_size=int(feature_payload["max_pkt_size"]),
            max_iat=float(feature_payload["max_iat"]),
            time_semantics=str(feature_payload["time_semantics"]),
            packet_length_semantics=str(feature_payload["packet_length_semantics"]),
            direction_semantics=str(feature_payload["direction_semantics"]),
        )
        architecture_payload = payload.get("architecture") or {}
        architecture = ModelArchitecture(
            embed_dim=int(architecture_payload["embed_dim"]),
            num_heads=int(architecture_payload["num_heads"]),
            num_layers=int(architecture_payload["num_layers"]),
            ff_dim=int(architecture_payload["ff_dim"]),
            dropout=float(architecture_payload["dropout"]),
            num_classes=int(architecture_payload["num_classes"]),
        )
        if feature_profile.name != "legacy-zeek-v1":
            raise ValueError("unsupported model feature profile")
        if feature_profile.time_semantics != "since_flow_start":
            raise ValueError("unsupported feature time semantics")
        if feature_profile.packet_length_semantics != "tcp_payload_plus_54":
            raise ValueError("unsupported packet length semantics")
        if feature_profile.direction_semantics != "tcp_initiator":
            raise ValueError("unsupported packet direction semantics")
        if not 1 <= feature_profile.capture_packets <= feature_profile.max_len:
            raise ValueError("capture_packets must be between 1 and max_len")
        if not 1 <= feature_profile.min_packets <= feature_profile.capture_packets:
            raise ValueError("min_packets must be between 1 and capture_packets")

        return cls(
            schema_version=1,
            model_id=str(payload["model_id"]),
            checkpoint_sha256=expected_hash,
            threshold=float(payload["threshold"]),
            architecture=architecture,
            feature_profile=feature_profile,
        )


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
