from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mineshark.sensor.features import encode_legacy_zeek_features  # noqa: E402
from mineshark.sensor.capture import read_capture  # noqa: E402
from mineshark.sensor.flow import CompletedFlow, FlowAssembler  # noqa: E402
from mineshark.sensor.inference import TorchTransformerScorer  # noqa: E402
from mineshark.sensor.manifest import ModelManifest  # noqa: E402


def _load_legacy_module(path: Path):
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location("mineshark_legacy_predict_scan", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load legacy predictor: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _legacy_model(torch, legacy, checkpoint_path: Path):
    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
    config = checkpoint["config"]
    model = legacy.TrafficTransformer(
        vocab_size=config["max_pkt_size"] + 2,
        seq_len=config["max_len"],
        embed_dim=config["embed_dim"],
        num_heads=config["num_heads"],
        num_layers=config["num_layers"],
        ff_dim=config["ff_dim"],
        dropout=config["dropout"],
        num_classes=2,
    )
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()
    return model, config


def verify(args: argparse.Namespace) -> dict:
    import torch

    manifest = ModelManifest.load(args.manifest, args.checkpoint)
    legacy = _load_legacy_module(args.legacy_predictor)
    old_model, config = _legacy_model(torch, legacy, args.checkpoint)
    new_scorer = TorchTransformerScorer(manifest, args.checkpoint)
    new_scorer.validate()

    checked = 0
    feature_mismatches = 0
    max_score_error = 0.0
    flow_results = []
    sensor_flows = []
    if args.pcap is not None:
        capture = read_capture(args.pcap)
        assembler = FlowAssembler(
            max_packets=manifest.feature_profile.capture_packets,
            min_packets=manifest.feature_profile.min_packets,
            idle_timeout=30.0,
            active_timeout=120.0,
        )
        for packet in capture.packets:
            sensor_flows.extend(assembler.add(packet))
    sensor_flow_index = 0
    producer_mismatches = 0
    for raw_line in args.legacy_log.read_text(encoding="utf-8", errors="ignore").splitlines():
        parsed = legacy.parse_line(
            raw_line,
            max_len=config["max_len"],
            max_pkt_size=config["max_pkt_size"],
            max_iat=config["max_iat"],
        )
        if parsed is None:
            continue
        old_sizes, old_iats, old_directions, old_mask, meta = parsed
        parts = raw_line.split("\t")
        signed_sizes = tuple(int(value) for value in parts[6].split(",") if value)
        offsets = tuple(float(value) for value in parts[7].split(",") if value)
        sequence_length = min(len(signed_sizes), len(offsets), manifest.feature_profile.capture_packets)
        flow = CompletedFlow(
            src_ip=str(meta.get("src_ip", "unknown")),
            src_port=int(meta.get("src_port", 0)),
            dst_ip=str(meta.get("dst_ip", "unknown")),
            dst_port=int(meta.get("dst_port", 0)),
            protocol=str(meta.get("proto", "tcp")),
            started_at=0.0,
            ended_at=offsets[sequence_length - 1],
            signed_packet_sizes=signed_sizes[:sequence_length],
            time_offsets=offsets[:sequence_length],
            close_reason="golden_parity",
        )
        producer_match = None
        if args.pcap is not None:
            if sensor_flow_index >= len(sensor_flows):
                producer_match = False
            else:
                sensor_flow = sensor_flows[sensor_flow_index]
                producer_match = (
                    (sensor_flow.src_ip, sensor_flow.src_port, sensor_flow.dst_ip, sensor_flow.dst_port)
                    == (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port)
                    and sensor_flow.signed_packet_sizes == flow.signed_packet_sizes
                    and sensor_flow.time_offsets == tuple(round(value, 6) for value in flow.time_offsets)
                )
                sensor_flow_index += 1
            if not producer_match:
                producer_mismatches += 1
        encoded = encode_legacy_zeek_features(
            flow,
            max_len=manifest.feature_profile.max_len,
            max_pkt_size=manifest.feature_profile.max_pkt_size,
            max_iat=manifest.feature_profile.max_iat,
        )
        new_sizes = torch.tensor([encoded.sizes], dtype=torch.long)
        new_iats = torch.tensor([encoded.iats], dtype=torch.float32).unsqueeze(-1)
        new_directions = torch.tensor([encoded.directions], dtype=torch.long)
        new_mask = torch.tensor([encoded.mask], dtype=torch.bool)
        feature_match = (
            new_sizes.tolist() == old_sizes.tolist()
            and new_iats.tolist() == old_iats.tolist()
            and new_directions.tolist() == old_directions.tolist()
            and new_mask.tolist() == old_mask.tolist()
        )
        if not feature_match:
            feature_mismatches += 1
        with torch.inference_mode():
            _, logits = old_model(old_sizes, old_iats, old_directions, attention_mask=old_mask)
            old_score = float(torch.softmax(logits, dim=1)[0, 1].item())
        new_score = new_scorer.score(flow)
        score_error = abs(old_score - new_score)
        max_score_error = max(max_score_error, score_error)
        checked += 1
        flow_results.append(
            {
                "uid": meta.get("uid"),
                "packet_count": sequence_length,
                "features_match": feature_match,
                "producer_match": producer_match,
                "old_score": old_score,
                "new_score": new_score,
                "absolute_error": score_error,
            }
        )

    if checked == 0:
        raise RuntimeError("golden log contains no usable flows")
    result = {
        "status": (
            "passed"
            if feature_mismatches == 0 and producer_mismatches == 0 and max_score_error <= args.tolerance
            else "failed"
        ),
        "flows_checked": checked,
        "feature_mismatches": feature_mismatches,
        "producer_mismatches": producer_mismatches,
        "max_score_error": max_score_error,
        "tolerance": args.tolerance,
        "model_sha256": manifest.checkpoint_sha256,
        "flows": flow_results,
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare the recovered legacy producer/model with the new Sensor")
    parser.add_argument("--legacy-predictor", type=Path, required=True)
    parser.add_argument("--legacy-log", type=Path, required=True)
    parser.add_argument("--pcap", type=Path)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--tolerance", type=float, default=1e-5)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = verify(args)
    text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
