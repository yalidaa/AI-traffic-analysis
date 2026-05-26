from __future__ import annotations

import argparse
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from mineshark.config import RuntimeConfig, resolve_project_path
from mineshark.agent.toolbox import AgentToolbox, build_langchain_tools


DEFAULT_OUTPUT_JSON = "outputs/reports/agent_audit_report.json"
DEFAULT_OUTPUT_MD = "outputs/reports/agent_audit_report.md"

SYSTEM_PROMPT = """你是 MineShark 安全研判 Agent，面向企业内网安全运营人员工作。

你运行在旁路研判模式：现有 mineshark-ai.timer 会持续写入 /var/log/ai_alerts.json，你不要修改或替换这个服务。
你必须优先调用 query_mineshark_ai_alerts 读取实时 AI 告警，再使用 Wazuh、Zeek、Suricata 与 RAG 工具补充证据，然后生成中文 Markdown 报告。

报告必须包含：
1. 总体结论
2. 时间线或事件脉络
3. MineShark AI 告警摘要
4. Wazuh/Zeek/Suricata 告警与上下文关联
5. RAG 知识依据
6. 建议排查动作
7. 误报与局限性提示

重要约束：
- 模型概率只能表述为风险线索，不能直接表述为攻击事实。
- 如果 /var/log/ai_alerts.json 为空，要明确说明当前没有实时 AI 告警，而不是编造风险。
- 如果某个工具失败，要在报告中说明失败原因或降级来源。
- 不要建议自动封禁、自动删除或自动处置，只给人工复核建议。
"""


def _message_to_dict(message: Any) -> Dict[str, Any]:
    if isinstance(message, dict):
        return message
    payload: Dict[str, Any] = {
        "type": getattr(message, "type", message.__class__.__name__),
        "content": getattr(message, "content", ""),
    }
    tool_calls = getattr(message, "tool_calls", None)
    if tool_calls:
        payload["tool_calls"] = tool_calls
    name = getattr(message, "name", None)
    if name:
        payload["name"] = name
    return payload


def serialise_messages(messages: List[Any]) -> List[Dict[str, Any]]:
    return [_message_to_dict(message) for message in messages]


def _last_text_message(messages: List[Any]) -> str:
    for message in reversed(messages):
        content = getattr(message, "content", "")
        if isinstance(content, str) and content.strip():
            return content.strip()
    return ""


def build_user_request(args: argparse.Namespace) -> str:
    context = {
        "task": args.task,
        "mode": "sidecar_read_existing_ai_alerts",
        "primary_ai_input": args.ai_alerts_path,
        "default_log_file": args.log_file,
        "target_ip": args.ip,
        "target_uid": args.uid,
        "start_time": args.start_time,
        "end_time": args.end_time,
        "threshold": args.threshold,
        "max_events": args.max_events,
        "top_k": args.top_k,
        "rerun_model_enabled": args.rerun_model,
    }
    return (
        "请基于以下运行参数完成一次安全研判。第一步必须调用 query_mineshark_ai_alerts 读取现有实时 AI 告警；"
        "随后按需调用 Wazuh、Zeek、Suricata 和 RAG 工具补充证据，最后输出 Markdown 报告。"
        "只有 rerun_model_enabled=true 时才允许重新运行模型推理。\n"
        + json.dumps(context, ensure_ascii=False, indent=2)
    )


def build_agent(config: RuntimeConfig, tools):
    if not config.deepseek_api_key:
        raise RuntimeError("DEEPSEEK_API_KEY is required for mineshark-agent-audit.")
    try:
        from langchain_openai import ChatOpenAI
        from langgraph.prebuilt import create_react_agent
    except Exception as exc:
        raise RuntimeError("langgraph and langchain-openai are required for the Agent CLI.") from exc

    model = ChatOpenAI(
        api_key=config.deepseek_api_key,
        base_url=config.deepseek_base_url,
        model=config.deepseek_model,
        temperature=0.2,
    )
    try:
        return create_react_agent(model, tools, prompt=SYSTEM_PROMPT)
    except TypeError:
        return create_react_agent(model, tools, state_modifier=SYSTEM_PROMPT)


def run_agent_audit(args: argparse.Namespace) -> Dict[str, Any]:
    config = RuntimeConfig.from_env(args.env_file)
    if args.ai_alerts_path:
        config = replace(config, mineshark_ai_alerts_path=resolve_project_path(args.ai_alerts_path))
    args.ai_alerts_path = str(config.mineshark_ai_alerts_path)
    warning = config.tls_warning()
    if warning:
        print(f"Warning: {warning}")

    toolbox = AgentToolbox(
        config=config,
        checkpoint=args.checkpoint,
        log_file=args.log_file,
        threshold=args.threshold,
        max_events=args.max_events,
        top_k=args.top_k,
    )
    tools = build_langchain_tools(toolbox, include_model_tool=args.rerun_model)
    agent = build_agent(config, tools)
    result = agent.invoke(
        {"messages": [{"role": "user", "content": build_user_request(args)}]},
        config={"recursion_limit": args.recursion_limit},
    )
    messages = list(result.get("messages", []))
    markdown = _last_text_message(messages)
    if not markdown:
        markdown = "# MineShark Agent 安全研判报告\n\nAgent 未返回可读报告，请检查 LLM 响应与工具调用日志。\n"

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input": {
            "task": args.task,
            "checkpoint": args.checkpoint,
            "log_file": args.log_file,
            "ai_alerts_path": args.ai_alerts_path,
            "ip": args.ip,
            "uid": args.uid,
            "start_time": args.start_time,
            "end_time": args.end_time,
            "threshold": args.threshold,
            "max_events": args.max_events,
            "top_k": args.top_k,
            "rerun_model": args.rerun_model,
        },
        "runtime": {
            "deepseek_model": config.deepseek_model,
            "rag_index_dir": str(config.rag_index_dir),
            "zeek_log_dir": str(config.zeek_log_dir),
            "suricata_eve_path": str(config.suricata_eve_path),
            "wazuh_alerts_path": str(config.wazuh_alerts_path),
            "mineshark_ai_alerts_path": str(config.mineshark_ai_alerts_path),
            "warning": warning,
        },
        "tool_trace": toolbox.trace,
        "agent_messages": serialise_messages(messages),
        "markdown_report": markdown,
    }
    return report


def write_report(report: Dict[str, Any], output_json: str, output_md: str) -> None:
    json_path = resolve_project_path(output_json)
    md_path = resolve_project_path(output_md)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    md_path.write_text(str(report["markdown_report"]).strip() + "\n", encoding="utf-8")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {md_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run MineShark LangGraph security triage Agent.")
    parser.add_argument("--env-file", default=None)
    parser.add_argument("--checkpoint", default="checkpoints/main_in_domain.pt")
    parser.add_argument("--log-file", default=None)
    parser.add_argument(
        "--ai-alerts-path",
        default=None,
        help="Override MINESHARK_AI_ALERTS_PATH. Defaults to /var/log/ai_alerts.json via .env/config.",
    )
    parser.add_argument("--ip", default=None)
    parser.add_argument("--uid", default=None)
    parser.add_argument("--start-time", default=None)
    parser.add_argument("--end-time", default=None)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--max-events", type=int, default=5)
    parser.add_argument("--top-k", type=int, default=4)
    parser.add_argument("--recursion-limit", type=int, default=18)
    parser.add_argument(
        "--rerun-model",
        action="store_true",
        help="Expose the Transformer inference tool as a fallback. Default mode only reads ai_alerts.json.",
    )
    parser.add_argument("--task", default="生成一次谨慎、带证据链的中文安全研判报告。")
    parser.add_argument("--output-json", default=DEFAULT_OUTPUT_JSON)
    parser.add_argument("--output-md", default=DEFAULT_OUTPUT_MD)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    report = run_agent_audit(args)
    write_report(report, args.output_json, args.output_md)


if __name__ == "__main__":
    main()
