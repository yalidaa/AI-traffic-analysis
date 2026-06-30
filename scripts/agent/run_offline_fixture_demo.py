from __future__ import annotations

import argparse
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterator


ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mineshark.agent.cli import run_agent_audit, write_report


@contextmanager
def temporary_env(values: Dict[str, str]) -> Iterator[None]:
    previous = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run MineShark offline fixture demo without external LLM/RAG services.")
    parser.add_argument("--fixture-dir", default="tests/fixtures/demo_event")
    parser.add_argument("--output-dir", default="outputs/offline_demo")
    parser.add_argument("--alert-id", default="demo-alert-001")
    parser.add_argument("--uid", default="Cdemo1")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--max-events", type=int, default=5)
    return parser


def main() -> None:
    cli_args = build_parser().parse_args()
    fixture_dir = Path(cli_args.fixture_dir)
    if not fixture_dir.is_absolute():
        fixture_dir = ROOT / fixture_dir
    output_dir = Path(cli_args.output_dir)
    if not output_dir.is_absolute():
        output_dir = ROOT / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    env = {
        "MINESHARK_AI_ALERTS_PATH": str(fixture_dir / "ai_alerts.json"),
        "WAZUH_ALERTS_PATH": str(fixture_dir / "alerts.json"),
        "ZEEK_LOG_DIR": str(fixture_dir),
        "SURICATA_EVE_PATH": str(fixture_dir / "eve.json"),
        "MINESHARK_KNOWLEDGE_FILE": str(fixture_dir / "knowledge.jsonl"),
        "MINESHARK_RAG_INDEX_DIR": str(fixture_dir / "rag"),
        "WAZUH_INDEXER_URL": "https://127.0.0.1:9",
        "WAZUH_TIMEOUT": "1",
        "WAZUH_VERIFY_SSL": "false",
    }

    args = argparse.Namespace(
        env_file=None,
        checkpoint="checkpoints/main_in_domain.pt",
        log_file=None,
        ai_alerts_path=None,
        alert_id=cli_args.alert_id,
        ip=None,
        uid=cli_args.uid,
        start_time=None,
        end_time=None,
        threshold=cli_args.threshold,
        max_events=cli_args.max_events,
        top_k=4,
        recursion_limit=18,
        preflight_only=False,
        preflight_check_wazuh_api=False,
        evidence_only=True,
        strict_report_quality=False,
        rerun_model=False,
        task="离线 fixture 演示：生成不依赖外部大模型的确定性研判报告。",
        output_json=str(output_dir / "offline_agent_report.json"),
        output_md=str(output_dir / "offline_agent_report.md"),
    )
    with temporary_env(env):
        report = run_agent_audit(args)
    write_report(report, args.output_json, args.output_md)
    print(f"Report status: {report['report_status']}")
    print(f"Tool calls: {len(report['tool_trace'])}")


if __name__ == "__main__":
    main()
