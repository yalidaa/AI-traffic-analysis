import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import requests
import torch
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from model import TrafficTransformer


DEFAULT_KNOWLEDGE_PATH = SCRIPT_DIR / "knowledge" / "security_playbook.jsonl"
DEFAULT_OUTPUT_JSON = SCRIPT_DIR / "outputs" / "audit_report.json"
DEFAULT_OUTPUT_MD = SCRIPT_DIR / "outputs" / "audit_report.md"


def resolve_path(path: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = REPO_ROOT / candidate
    return candidate.resolve()


def parse_vector(raw: str, cast_type):
    if raw in {"(empty)", "-", ""}:
        return None
    try:
        return [cast_type(x) for x in raw.split(",") if x != ""]
    except ValueError:
        return None


def summarize_iats(iats: List[float]) -> Dict[str, float]:
    if not iats:
        return {"min": 0.0, "max": 0.0, "mean": 0.0, "median": 0.0}
    arr = np.asarray(iats, dtype=np.float64)
    return {
        "min": float(np.min(arr)),
        "max": float(np.max(arr)),
        "mean": float(np.mean(arr)),
        "median": float(np.median(arr)),
    }


def build_evidence(pkt_sizes: List[int], pkt_iats: List[float], resp_p: str) -> List[str]:
    evidence = []
    packet_count = len(pkt_sizes)
    positive = sum(1 for x in pkt_sizes if x > 0)
    negative = sum(1 for x in pkt_sizes if x < 0)
    large_packets = sum(1 for x in pkt_sizes if abs(x) >= 1400)
    iat_stats = summarize_iats(pkt_iats)

    evidence.append(f"连接包含 {packet_count} 个包，出入方向包数量约为 {positive}/{negative}。")
    if large_packets:
        evidence.append(f"存在 {large_packets} 个接近 MTU 的大包，可能对应批量传输或载荷交换。")
    if packet_count <= 4:
        evidence.append("连接包数较少，单条事件证据有限，需要结合上下文交叉验证。")
    if iat_stats["median"] < 0.01 and packet_count >= 5:
        evidence.append("包间隔中位数较低，短时间内出现密集交互。")
    if iat_stats["max"] >= 1.0:
        evidence.append("包间隔中存在秒级停顿，可能是周期性通信或交互式会话特征。")
    if resp_p not in {"80", "443", "53", "22", "25", "110", "143", "993", "995", "389", "445"}:
        evidence.append(f"目的端口 {resp_p} 不是常见 Web/邮件/DNS/管理端口，建议核查业务归属。")
    return evidence


def parse_mineshark_events(
    log_file: Path,
    max_len: int,
    min_packets: int,
    max_pkt_size: int,
    max_iat: float,
) -> List[Dict]:
    events = []
    source = log_file.name

    with log_file.open("r", encoding="utf-8", errors="ignore") as handle:
        for line_no, line in enumerate(handle, start=1):
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 8:
                continue

            pkt_sizes = parse_vector(parts[6], int)
            pkt_iats = parse_vector(parts[7], float)
            if pkt_sizes is None or pkt_iats is None:
                continue
            if len(pkt_sizes) < min_packets:
                continue

            seq_len = min(len(pkt_sizes), len(pkt_iats), max_len)
            raw_sizes = pkt_sizes[:seq_len]
            raw_iats = pkt_iats[:seq_len]

            size_tokens = []
            dir_tokens = []
            iat_values = []
            attn_mask = [1] * seq_len
            for raw_size, raw_iat in zip(raw_sizes, raw_iats):
                abs_size = min(abs(raw_size), max_pkt_size)
                size_tokens.append(abs_size + 1)
                dir_tokens.append(1 if raw_size > 0 else 2 if raw_size < 0 else 0)
                iat_values.append(float(np.clip(raw_iat, 0.0, max_iat)))

            pad_len = max_len - seq_len
            if pad_len > 0:
                size_tokens.extend([0] * pad_len)
                dir_tokens.extend([0] * pad_len)
                iat_values.extend([0.0] * pad_len)
                attn_mask.extend([0] * pad_len)

            context = {
                "line_no": line_no,
                "ts": parts[0],
                "uid": parts[1],
                "id_orig_h": parts[2],
                "id_orig_p": parts[3],
                "id_resp_h": parts[4],
                "id_resp_p": parts[5],
                "source_file": source,
                "packet_count": seq_len,
                "packet_sizes_preview": raw_sizes[:16],
                "packet_iats_preview": [round(x, 6) for x in raw_iats[:16]],
                "direction_counts": {
                    "orig_to_resp": sum(1 for x in raw_sizes if x > 0),
                    "resp_to_orig": sum(1 for x in raw_sizes if x < 0),
                    "zero": sum(1 for x in raw_sizes if x == 0),
                },
                "iat_stats": summarize_iats(raw_iats),
                "abs_bytes_total": int(sum(abs(x) for x in raw_sizes)),
                "evidence": build_evidence(raw_sizes, raw_iats, parts[5]),
            }
            events.append(
                {
                    "context": context,
                    "tensor": {
                        "sizes": size_tokens,
                        "iats": iat_values,
                        "dirs": dir_tokens,
                        "mask": attn_mask,
                    },
                }
            )

    return events


def load_model(checkpoint_path: Path, device: torch.device):
    checkpoint = torch.load(checkpoint_path, map_location=device, weights_only=False)
    config = checkpoint.get("config", {})
    max_pkt_size = int(config.get("max_pkt_size", 2000))
    max_len = int(config.get("max_len", 128))

    model = TrafficTransformer(
        vocab_size=max_pkt_size + 2,
        seq_len=max_len,
        embed_dim=int(config.get("embed_dim", 128)),
        num_heads=int(config.get("num_heads", 4)),
        num_layers=int(config.get("num_layers", 2)),
        ff_dim=int(config.get("ff_dim", 256)),
        dropout=float(config.get("dropout", 0.1)),
        num_classes=2,
    ).to(device)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()
    return model, config


def infer_events(model, events: List[Dict], device: torch.device, batch_size: int) -> List[Dict]:
    scored = []
    with torch.no_grad():
        for start in range(0, len(events), batch_size):
            batch_events = events[start : start + batch_size]
            sizes = torch.tensor([e["tensor"]["sizes"] for e in batch_events], dtype=torch.long).to(device)
            iats = (
                torch.tensor([e["tensor"]["iats"] for e in batch_events], dtype=torch.float32)
                .unsqueeze(-1)
                .to(device)
            )
            dirs = torch.tensor([e["tensor"]["dirs"] for e in batch_events], dtype=torch.long).to(device)
            mask = torch.tensor([e["tensor"]["mask"] for e in batch_events], dtype=torch.bool).to(device)

            _, logits = model(sizes, iats, dirs, attention_mask=mask)
            probs = torch.softmax(logits, dim=1).cpu().numpy()
            preds = np.argmax(probs, axis=1)

            for event, prob, pred in zip(batch_events, probs, preds):
                malware_probability = float(prob[1])
                benign_probability = float(prob[0])
                result = dict(event["context"])
                result.update(
                    {
                        "predicted_label": "malware" if int(pred) == 1 else "benign",
                        "malware_probability": malware_probability,
                        "benign_probability": benign_probability,
                        "risk_level": classify_risk(malware_probability),
                    }
                )
                scored.append(result)
    return scored


def classify_risk(malware_probability: float) -> str:
    if malware_probability >= 0.9:
        return "high"
    if malware_probability >= 0.7:
        return "medium"
    if malware_probability >= 0.5:
        return "low"
    return "informational"


def load_knowledge(path: Path) -> List[Dict[str, str]]:
    records = []
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def event_query(event: Dict) -> str:
    return " ".join(
        [
            event.get("predicted_label", ""),
            event.get("risk_level", ""),
            f"port_{event.get('id_resp_p', '')}",
            f"src_{event.get('id_orig_h', '')}",
            f"dst_{event.get('id_resp_h', '')}",
            " ".join(event.get("evidence", [])),
        ]
    )


def retrieve_knowledge(events: List[Dict], knowledge: List[Dict], top_k: int) -> List[Dict]:
    if not events or not knowledge or top_k <= 0:
        return []

    documents = []
    for item in knowledge:
        documents.append(
            " ".join(
                [
                    item.get("title", ""),
                    " ".join(item.get("tags", [])),
                    item.get("content", ""),
                    item.get("recommendation", ""),
                ]
            )
        )
    query = " ".join(event_query(event) for event in events)

    vectorizer = TfidfVectorizer(token_pattern=r"(?u)\b\w+\b")
    matrix = vectorizer.fit_transform(documents + [query])
    scores = cosine_similarity(matrix[-1], matrix[:-1]).flatten()
    ranked = np.argsort(scores)[::-1][:top_k]

    matches = []
    for idx in ranked:
        item = dict(knowledge[int(idx)])
        item["score"] = float(scores[int(idx)])
        matches.append(item)
    return matches


def compact_events_for_prompt(events: List[Dict]) -> List[Dict]:
    compact = []
    for idx, event in enumerate(events, start=1):
        compact.append(
            {
                "event_id": idx,
                "risk_level": event["risk_level"],
                "malware_probability": round(event["malware_probability"], 4),
                "uid": event["uid"],
                "src": f"{event['id_orig_h']}:{event['id_orig_p']}",
                "dst": f"{event['id_resp_h']}:{event['id_resp_p']}",
                "packet_count": event["packet_count"],
                "abs_bytes_total": event["abs_bytes_total"],
                "direction_counts": event["direction_counts"],
                "iat_stats": event["iat_stats"],
                "evidence": event["evidence"],
            }
        )
    return compact


def build_prompt(events: List[Dict], knowledge_matches: List[Dict]) -> List[Dict[str, str]]:
    payload = {
        "task": "为安全运营人员生成中文安全审计报告。不要夸大结论，要说明模型误报边界。",
        "events": compact_events_for_prompt(events),
        "knowledge_matches": knowledge_matches,
        "required_sections": [
            "总体结论",
            "高风险连接摘要",
            "可疑依据",
            "可能攻击阶段或安全含义",
            "建议排查动作",
            "误报与局限性提示",
        ],
    }
    system = (
        "你是企业内网安全运营分析助手。你会基于 AI 模型输出、Zeek/MineShark 流量元数据和"
        "安全知识库片段生成审计报告。必须谨慎表达，不能把模型概率直接等同于攻击事实。"
    )
    user = "请根据以下 JSON 生成 Markdown 格式中文报告：\n" + json.dumps(
        payload, ensure_ascii=False, indent=2
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def call_deepseek(messages: List[Dict[str, str]], timeout: int) -> Optional[str]:
    api_key = os.getenv("DEEPSEEK_API_KEY")
    base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

    if not api_key:
        return None

    endpoint = base_url.rstrip("/")
    if not endpoint.endswith("/chat/completions"):
        endpoint = endpoint + "/v1/chat/completions"

    response = requests.post(
        endpoint,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": messages,
            "temperature": 0.2,
        },
        timeout=timeout,
    )
    response.raise_for_status()
    data = response.json()
    return data["choices"][0]["message"]["content"]


def render_rule_based_report(events: List[Dict], knowledge_matches: List[Dict], log_file: Path) -> str:
    lines = [
        "# MineShark 安全分析报告",
        "",
        "## 总体结论",
        "",
        f"本次分析对象为 `{log_file}`，报告基于 Transformer 模型推理结果、MineShark 流量元数据和本地安全知识库生成。",
    ]
    if events:
        max_prob = max(event["malware_probability"] for event in events)
        high_count = sum(1 for event in events if event["risk_level"] == "high")
        lines.append(
            f"共选取 {len(events)} 条高风险候选连接进行研判，最高恶意概率为 {max_prob:.4f}，其中高风险连接 {high_count} 条。"
        )
    else:
        lines.append("未发现超过当前阈值的高风险候选连接。")

    lines.extend(["", "## 高风险连接摘要", ""])
    for idx, event in enumerate(events, start=1):
        lines.extend(
            [
                f"### 事件 {idx}: {event['id_orig_h']}:{event['id_orig_p']} -> {event['id_resp_h']}:{event['id_resp_p']}",
                "",
                f"- 风险等级：{event['risk_level']}",
                f"- 恶意概率：{event['malware_probability']:.4f}",
                f"- Zeek UID：{event['uid']}",
                f"- 包数量：{event['packet_count']}，绝对字节量：{event['abs_bytes_total']}",
                f"- 方向统计：{event['direction_counts']}",
                f"- IAT 摘要：{event['iat_stats']}",
                "- 可疑依据：",
            ]
        )
        for evidence in event["evidence"]:
            lines.append(f"  - {evidence}")
        lines.append("")

    lines.extend(["## 知识库参考", ""])
    for item in knowledge_matches:
        lines.append(f"- **{item.get('title', '未命名条目')}**：{item.get('content', '')}")

    lines.extend(
        [
            "",
            "## 建议排查动作",
            "",
            "- 在 Wazuh/Zeek 侧按源 IP、目的 IP、目的端口和时间窗口回溯相邻连接。",
            "- 核查目的地址是否属于已知业务、CDN、更新服务或内部基础设施。",
            "- 对高概率事件优先关联 Suricata 规则告警、DNS 查询、HTTP/TLS 元数据和主机日志。",
            "- 如确认是业务正常连接，可将该业务模式沉淀为白名单或低优先级观察规则。",
            "",
            "## 误报与局限性提示",
            "",
            "本报告中的风险等级来自模型概率和元数据证据融合，不能单独作为攻击定性结论。当前模型仍存在 benign 误报偏高的问题，需要结合规则告警、资产归属和主机行为进一步确认。",
        ]
    )
    return "\n".join(lines) + "\n"


def risk_counts(events: List[Dict]) -> Dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0, "informational": 0}
    for event in events:
        counts[event["risk_level"]] += 1
    return counts


def main():
    parser = argparse.ArgumentParser(description="Generate MineShark security audit reports.")
    parser.add_argument("--checkpoint", default="checkpoints/main_in_domain.pt")
    parser.add_argument("--log-file", required=True)
    parser.add_argument("--knowledge-file", default=str(DEFAULT_KNOWLEDGE_PATH))
    parser.add_argument("--output-json", default=str(DEFAULT_OUTPUT_JSON))
    parser.add_argument("--output-md", default=str(DEFAULT_OUTPUT_MD))
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--max-events", type=int, default=5)
    parser.add_argument("--top-knowledge", type=int, default=4)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--min-packets", type=int, default=None)
    parser.add_argument("--max-len", type=int, default=None)
    parser.add_argument("--max-pkt-size", type=int, default=None)
    parser.add_argument("--max-iat", type=float, default=None)
    parser.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    parser.add_argument("--no-llm", action="store_true", help="Generate a rule-based report without DeepSeek.")
    parser.add_argument("--llm-timeout", type=int, default=60)
    args = parser.parse_args()

    checkpoint_path = resolve_path(args.checkpoint)
    log_file = resolve_path(args.log_file)
    knowledge_file = resolve_path(args.knowledge_file)
    output_json = resolve_path(args.output_json)
    output_md = resolve_path(args.output_md)
    device = torch.device(args.device)

    model, config = load_model(checkpoint_path, device)
    max_len = int(args.max_len or config.get("max_len", 128))
    min_packets = int(args.min_packets or config.get("min_packets", 3))
    max_pkt_size = int(args.max_pkt_size or config.get("max_pkt_size", 2000))
    max_iat = float(args.max_iat or config.get("max_iat", 10.0))

    raw_events = parse_mineshark_events(
        log_file=log_file,
        max_len=max_len,
        min_packets=min_packets,
        max_pkt_size=max_pkt_size,
        max_iat=max_iat,
    )
    scored_events = infer_events(model, raw_events, device=device, batch_size=args.batch_size)
    candidates = [event for event in scored_events if event["malware_probability"] >= args.threshold]
    candidates.sort(key=lambda x: x["malware_probability"], reverse=True)
    selected_events = candidates[: args.max_events]

    knowledge = load_knowledge(knowledge_file)
    knowledge_matches = retrieve_knowledge(selected_events, knowledge, args.top_knowledge)

    llm_used = False
    llm_error = None
    if args.no_llm:
        markdown_report = render_rule_based_report(selected_events, knowledge_matches, log_file)
    else:
        try:
            llm_report = call_deepseek(build_prompt(selected_events, knowledge_matches), args.llm_timeout)
            if llm_report:
                markdown_report = llm_report.strip() + "\n"
                llm_used = True
            else:
                llm_error = "DEEPSEEK_API_KEY is not set; generated rule-based fallback report."
                markdown_report = render_rule_based_report(selected_events, knowledge_matches, log_file)
        except Exception as exc:
            llm_error = str(exc)
            markdown_report = render_rule_based_report(selected_events, knowledge_matches, log_file)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input": {
            "checkpoint": str(checkpoint_path),
            "log_file": str(log_file),
            "knowledge_file": str(knowledge_file),
            "threshold": args.threshold,
            "max_events": args.max_events,
        },
        "model": {
            "class": "TrafficTransformer",
            "config": {
                "max_len": max_len,
                "min_packets": min_packets,
                "max_pkt_size": max_pkt_size,
                "max_iat": max_iat,
            },
        },
        "llm": {
            "used": llm_used,
            "provider": "deepseek-compatible-api",
            "model": os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
            "error": llm_error,
        },
        "summary": {
            "total_valid_connections": len(scored_events),
            "connections_above_threshold": len(candidates),
            "reported_events": len(selected_events),
            "max_malware_probability": max(
                [event["malware_probability"] for event in scored_events], default=0.0
            ),
            "risk_counts": risk_counts(selected_events),
        },
        "knowledge_matches": knowledge_matches,
        "events": selected_events,
    }

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    output_md.write_text(markdown_report, encoding="utf-8")

    print(f"Loaded valid connections: {len(scored_events)}")
    print(f"Connections above threshold: {len(candidates)}")
    print(f"Reported events: {len(selected_events)}")
    print(f"JSON report: {output_json}")
    print(f"Markdown report: {output_md}")
    if llm_error:
        print(f"LLM fallback: {llm_error}")


if __name__ == "__main__":
    main()
