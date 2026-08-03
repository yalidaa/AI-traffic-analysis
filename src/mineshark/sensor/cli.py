from __future__ import annotations

import argparse
import json
import signal
from stat import S_ISREG
import sys
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from mineshark.sensor.capture import CaptureReadError
from mineshark.sensor.config import SensorConfig
from mineshark.sensor.runtime import SensorRuntime


DEFAULT_CONFIG_PATH = "/etc/mineshark/sensor.toml"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mineshark-sensor", description="MineShark offline traffic sensor")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="Sensor TOML configuration path")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate-config", help="Validate configuration, model hash, and checkpoint compatibility")
    subparsers.add_parser("run", help="Process closed dumpcap ring files continuously")
    replay = subparsers.add_parser("replay", help="Replay one or more PCAP/PCAPNG files")
    replay.add_argument("captures", nargs="+", type=Path)
    replay.add_argument("--output", type=Path, help="Replay JSONL output path with isolated state")
    subparsers.add_parser("status", help="Print the last local sensor status")
    return parser


def discover_closed_captures(spool_dir: str | Path, *, rotate_seconds: int, now: float) -> list[Path]:
    root = Path(spool_dir)
    if not root.is_dir():
        return []
    candidates: list[tuple[Path, int, float]] = []
    for pattern in ("*.pcap", "*.pcapng"):
        for path in root.glob(pattern):
            try:
                metadata = path.stat()
            except FileNotFoundError:
                continue
            if S_ISREG(metadata.st_mode):
                candidates.append((path, metadata.st_mtime_ns, metadata.st_mtime))
    candidates.sort(key=lambda item: (item[1], item[0].name))
    if not candidates:
        return []
    newest = candidates[-1]
    stable_age = now - newest[2]
    if stable_age <= rotate_seconds + 1:
        return [item[0] for item in candidates[:-1]]
    return [item[0] for item in candidates]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "status":
        config = SensorConfig.load(args.config, verify_model=False)
        return _print_status(config)

    config = SensorConfig.load(args.config, verify_model=True)
    if args.command == "validate-config":
        runtime = SensorRuntime(config)
        runtime.validate_model()
        print(
            json.dumps(
                {
                    "ok": True,
                    "sensor_id": config.sensor_id,
                    "interface": config.interface,
                    "model_id": config.model_manifest.model_id,
                    "model_sha256": config.model_manifest.checkpoint_sha256,
                    "feature_profile": config.model_manifest.feature_profile.name,
                    "threshold": config.model.threshold,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    if args.command == "replay":
        return _replay(config, args.captures, output=args.output)
    if args.command == "run":
        return _run(config)
    raise ValueError(f"unsupported command: {args.command}")


def _print_status(config: SensorConfig) -> int:
    path = config.output.status_path
    if not path.is_file():
        print(
            json.dumps(
                {"schema_version": 1, "sensor_id": config.sensor_id, "status": "unknown", "error": "status not found"},
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 1
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False, sort_keys=True))
        return 1
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


def _replay(config: SensorConfig, captures: list[Path], *, output: Path | None) -> int:
    if output is not None:
        replay_output = replace(
            config.output,
            events_path=output,
            status_path=output.with_suffix(output.suffix + ".status.json"),
            state_path=output.with_suffix(output.suffix + ".state.sqlite3"),
        )
        config = replace(config, output=replay_output)
    runtime = SensorRuntime(config)
    runtime.validate_model()
    summaries = []
    ordered = sorted(captures, key=lambda path: str(path))
    for index, capture in enumerate(ordered):
        summaries.append(runtime.process_capture(capture, finalize=index == len(ordered) - 1))
    runtime.emit_heartbeat()
    print(json.dumps({"captures": summaries, "status": "complete"}, ensure_ascii=False, sort_keys=True))
    return 0


def _run(config: SensorConfig) -> int:
    runtime = SensorRuntime(config)
    runtime.validate_model()
    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    for signal_name in ("SIGINT", "SIGTERM"):
        signum = getattr(signal, signal_name, None)
        if signum is not None:
            signal.signal(signum, stop)

    last_heartbeat = 0.0
    while not stopping:
        now = time.time()
        captures = discover_closed_captures(
            config.capture.spool_dir,
            rotate_seconds=config.capture.rotate_seconds,
            now=now,
        )
        pending_captures = [capture for capture in captures if not runtime.capture_processed(capture)]
        for capture in pending_captures:
            try:
                runtime.process_capture(capture)
            except FileNotFoundError as exc:
                print(
                    json.dumps({"capture": str(capture), "error": str(exc), "status": "skipped_rotation"}),
                    file=sys.stderr,
                    flush=True,
                )
            except CaptureReadError as exc:
                print(
                    json.dumps({"capture": str(capture), "error": str(exc), "status": "quarantined"}),
                    file=sys.stderr,
                    flush=True,
                )
        runtime.expire_flows(now=now)
        if now - last_heartbeat >= 15.0:
            runtime.emit_heartbeat(
                observed_at=datetime.now(timezone.utc),
                capture_backlog=len(pending_captures),
            )
            last_heartbeat = now
        time.sleep(min(config.poll_seconds, 1.0))
    runtime.emit_heartbeat(observed_at=datetime.now(timezone.utc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
