from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence


MALWARE_LABELS = {"malware", "attack", "malicious", "c2", "tunnel", "bruteforce", "1", 1, True}
BENIGN_LABELS = {"benign", "normal", "safe", "0", 0, False}


@dataclass(frozen=True)
class CompetitionScenario:
    scenario_id: str
    category: str
    label: str
    score: float
    description: str
    protocol: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int | None = None
    evidence: tuple[str, ...] = ()
    expected_behavior: str = ""

    @property
    def actual_malware(self) -> bool:
        return _normalise_label(self.label)

    def to_record(self) -> Dict[str, Any]:
        return {
            "id": self.scenario_id,
            "category": self.category,
            "label": self.label,
            "score": self.score,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "description": self.description,
            "evidence": list(self.evidence),
            "expected_behavior": self.expected_behavior,
        }


def _normalise_label(label: Any) -> bool:
    if isinstance(label, str):
        lowered = label.strip().lower()
        if lowered in MALWARE_LABELS:
            return True
        if lowered in BENIGN_LABELS:
            return False
    elif label in MALWARE_LABELS:
        return True
    elif label in BENIGN_LABELS:
        return False
    raise ValueError(f"Unsupported scenario label: {label!r}")


def _safe_float(value: Any, *, field_name: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be a number, got {value!r}") from exc


def _safe_port(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"dst_port must be an integer, got {value!r}") from exc


def scenario_from_record(record: Dict[str, Any]) -> CompetitionScenario:
    scenario_id = str(record.get("id") or record.get("scenario_id") or "").strip()
    if not scenario_id:
        raise ValueError("scenario record is missing id")
    label = record.get("label")
    _normalise_label(label)
    evidence = record.get("evidence") or ()
    if isinstance(evidence, str):
        evidence = [evidence]
    return CompetitionScenario(
        scenario_id=scenario_id,
        category=str(record.get("category") or "uncategorized"),
        label=str(label),
        score=_safe_float(record.get("score"), field_name="score"),
        protocol=str(record.get("protocol") or ""),
        src_ip=str(record.get("src_ip") or ""),
        dst_ip=str(record.get("dst_ip") or ""),
        dst_port=_safe_port(record.get("dst_port")),
        description=str(record.get("description") or ""),
        evidence=tuple(str(item) for item in evidence),
        expected_behavior=str(record.get("expected_behavior") or ""),
    )


def load_scenarios(path: str | Path) -> List[CompetitionScenario]:
    source = Path(path)
    if source.is_dir():
        source = source / "scenarios.jsonl"
    if not source.exists():
        raise FileNotFoundError(f"scenario file not found: {source}")

    if source.suffix.lower() == ".json":
        raw = json.loads(source.read_text(encoding="utf-8"))
        records = raw.get("scenarios", raw) if isinstance(raw, dict) else raw
        if not isinstance(records, list):
            raise ValueError("JSON scenario file must contain a list or {'scenarios': [...]}")
        return [scenario_from_record(record) for record in records]

    scenarios: List[CompetitionScenario] = []
    for lineno, line in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON on {source}:{lineno}: {exc}") from exc
        scenarios.append(scenario_from_record(record))
    return scenarios


def _prf(tp: int, fp: int, tn: int, fn: int) -> Dict[str, float]:
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "accuracy": (tp + tn) / total if total else 0.0,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "fnr": fn / (fn + tp) if fn + tp else 0.0,
    }


def _confusion(rows: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    tp = sum(1 for row in rows if row["actual"] == "malware" and row["predicted"] == "malware")
    fp = sum(1 for row in rows if row["actual"] == "benign" and row["predicted"] == "malware")
    tn = sum(1 for row in rows if row["actual"] == "benign" and row["predicted"] == "benign")
    fn = sum(1 for row in rows if row["actual"] == "malware" and row["predicted"] == "benign")
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def evaluate_scenarios(scenarios: Iterable[CompetitionScenario], threshold: float) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for scenario in scenarios:
        actual = "malware" if scenario.actual_malware else "benign"
        predicted = "malware" if scenario.score >= threshold else "benign"
        rows.append(
            {
                **scenario.to_record(),
                "actual": actual,
                "predicted": predicted,
                "correct": actual == predicted,
                "decision": "above_threshold" if scenario.score >= threshold else "below_threshold",
            }
        )

    matrix = _confusion(rows)
    metrics = {**matrix, **_prf(**matrix)}
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["category"]].append(row)

    categories = []
    for category, items in sorted(grouped.items()):
        cat_matrix = _confusion(items)
        categories.append(
            {
                "category": category,
                "count": len(items),
                "average_score": sum(float(item["score"]) for item in items) / len(items),
                **cat_matrix,
                **_prf(**cat_matrix),
            }
        )

    false_positives = [row for row in rows if row["actual"] == "benign" and row["predicted"] == "malware"]
    false_negatives = [row for row in rows if row["actual"] == "malware" and row["predicted"] == "benign"]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "threshold": threshold,
        "scenario_count": len(rows),
        "label_counts": {
            "benign": sum(1 for row in rows if row["actual"] == "benign"),
            "malware": sum(1 for row in rows if row["actual"] == "malware"),
        },
        "metrics": metrics,
        "categories": categories,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "rows": rows,
        "notes": [
            "Scores are risk clues from encrypted-traffic metadata, not final attack facts.",
            "False positives and false negatives must be reviewed with Wazuh, Zeek, Suricata, asset context, and analyst feedback.",
        ],
    }


def format_percent(value: float) -> str:
    return f"{value * 100:.1f}%"


def render_markdown(result: Dict[str, Any]) -> str:
    metrics = result["metrics"]
    lines = [
        "# MineShark 命题赛评测对比报告",
        "",
        "本报告面向第七题“面向加密通信协议的恶意行为检测技术”。评测只使用加密会话元数据、时序行为和平台告警线索，不依赖明文解密内容。",
        "",
        "## 1. 数据集概览",
        "",
        f"- 样本数：{result['scenario_count']}",
        f"- 正常样本：{result['label_counts']['benign']}",
        f"- 攻击样本：{result['label_counts']['malware']}",
        f"- 判定阈值：{result['threshold']:.2f}",
        "",
        "## 2. 核心指标",
        "",
        "| 指标 | 数值 |",
        "| --- | ---: |",
        f"| Accuracy | {format_percent(metrics['accuracy'])} |",
        f"| Precision | {format_percent(metrics['precision'])} |",
        f"| Recall | {format_percent(metrics['recall'])} |",
        f"| F1 | {format_percent(metrics['f1'])} |",
        f"| FPR | {format_percent(metrics['fpr'])} |",
        "",
        "## 3. 混淆矩阵",
        "",
        "| 项目 | 数量 |",
        "| --- | ---: |",
        f"| TP | {metrics['tp']} |",
        f"| FP | {metrics['fp']} |",
        f"| TN | {metrics['tn']} |",
        f"| FN | {metrics['fn']} |",
        "",
        "## 4. 场景对比",
        "",
        "| 场景 | 样本数 | 平均风险分 | Accuracy | FPR | 备注 |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for item in result["categories"]:
        note = "覆盖正常/攻击对照"
        lines.append(
            f"| {item['category']} | {item['count']} | {item['average_score']:.3f} | "
            f"{format_percent(item['accuracy'])} | {format_percent(item['fpr'])} | {note} |"
        )

    lines.extend(
        [
            "",
            "## 5. 误报与漏报样例",
            "",
            "### 误报样例",
        ]
    )
    if result["false_positives"]:
        for row in result["false_positives"]:
            lines.append(
                f"- `{row['id']}`：{row['description']}，风险分 {row['score']:.3f}。建议结合资产角色和业务白名单复核。"
            )
    else:
        lines.append("- 本轮评测未出现误报。")

    lines.append("")
    lines.append("### 漏报样例")
    if result["false_negatives"]:
        for row in result["false_negatives"]:
            lines.append(
                f"- `{row['id']}`：{row['description']}，风险分 {row['score']:.3f}。建议补充低频长周期行为特征。"
            )
    else:
        lines.append("- 本轮评测未出现漏报。")

    lines.extend(
        [
            "",
            "## 6. 研判边界",
            "",
            "MineShark 输出的是加密流量元数据风险线索，不能直接等同于攻击事实。正式研判需要结合 Wazuh 告警、Zeek 连接上下文、Suricata 规则命中、RAG playbook 和人工复核结论。",
            "",
        ]
    )
    return "\n".join(lines)


def write_table_csv(result: Dict[str, Any], output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["id", "category", "label", "score", "predicted", "correct", "protocol", "dst_port", "description"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in result["rows"]:
            writer.writerow({field: row.get(field, "") for field in fields})


def write_outputs(result: Dict[str, Any], output_dir: str | Path) -> Dict[str, str]:
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    metrics_path = target / "metrics.json"
    markdown_path = target / "comparison.md"
    table_path = target / "table_data.csv"
    metrics_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    markdown_path.write_text(render_markdown(result), encoding="utf-8")
    write_table_csv(result, table_path)
    return {
        "metrics": str(metrics_path),
        "comparison": str(markdown_path),
        "table_data": str(table_path),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run MineShark competition scenario evaluation.")
    parser.add_argument(
        "--scenario-dir",
        default="tests/fixtures/competition_scenarios",
        help="Directory containing scenarios.jsonl, or a direct .json/.jsonl scenario file.",
    )
    parser.add_argument("--output-dir", default="outputs/competition")
    parser.add_argument("--threshold", type=float, default=0.70)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    scenarios = load_scenarios(args.scenario_dir)
    result = evaluate_scenarios(scenarios, threshold=args.threshold)
    outputs = write_outputs(result, args.output_dir)
    print(f"Scenario count: {result['scenario_count']}")
    print(f"Accuracy: {result['metrics']['accuracy']:.4f}")
    print(f"Precision: {result['metrics']['precision']:.4f}")
    print(f"Recall: {result['metrics']['recall']:.4f}")
    print(f"F1: {result['metrics']['f1']:.4f}")
    for name, path in outputs.items():
        print(f"{name}: {path}")
