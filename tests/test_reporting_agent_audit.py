import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mineshark.reporting.agent_audit import (
    build_prompt,
    contrast_summary,
    render_rule_based_report,
    select_benign_controls,
)


def make_event(uid, malware_probability, risk_level="informational"):
    benign_probability = 1.0 - malware_probability
    return {
        "uid": uid,
        "id_orig_h": "10.0.0.5",
        "id_orig_p": "51514",
        "id_resp_h": "203.0.113.10",
        "id_resp_p": "443",
        "packet_count": 8,
        "abs_bytes_total": 2048,
        "direction_counts": {"orig_to_resp": 4, "resp_to_orig": 4, "zero": 0},
        "iat_stats": {"min": 0.001, "max": 0.5, "mean": 0.1, "median": 0.05},
        "evidence": ["连接包数足够，适合做元数据研判。"],
        "predicted_label": "malware" if malware_probability >= 0.5 else "benign",
        "malware_probability": malware_probability,
        "benign_probability": benign_probability,
        "risk_level": risk_level,
        "evidence_strength": "limited_metadata",
        "risk_explanation": "模型概率只是风险线索，需要结合上下文复核。",
    }


class ReportingAgentAuditTests(unittest.TestCase):
    def test_select_benign_controls_prefers_events_below_threshold(self):
        events = [
            make_event("high", 0.91, "high"),
            make_event("low-a", 0.12),
            make_event("low-b", 0.32),
        ]
        controls = select_benign_controls(events, max_events=2, benign_threshold=0.5, source_label="benign.log")

        self.assertEqual([event["uid"] for event in controls], ["low-a", "low-b"])
        self.assertEqual(controls[0]["control_source"], "benign.log")
        self.assertEqual(controls[0]["control_selection_reason"], "malware_probability_below_0.50")

    def test_select_benign_controls_falls_back_to_lowest_probability(self):
        events = [make_event("mid", 0.71, "medium"), make_event("high", 0.88, "medium")]
        controls = select_benign_controls(events, max_events=1, benign_threshold=0.5, source_label="primary.log")

        self.assertEqual(controls[0]["uid"], "mid")
        self.assertEqual(
            controls[0]["control_selection_reason"],
            "lowest_probability_fallback_no_event_below_threshold",
        )

    def test_rule_based_report_includes_benign_contrast_section(self):
        high_event = make_event("high", 0.95, "high")
        control = select_benign_controls(
            [make_event("control", 0.08)],
            max_events=1,
            benign_threshold=0.5,
            source_label="benign.log",
        )
        report = render_rule_based_report(
            [high_event],
            knowledge_matches=[],
            log_file=Path("malware.log"),
            benign_controls=control,
            benign_note="已选取低于良性阈值的连接作为对照样本。",
        )

        self.assertIn("## 良性对照样本", report)
        self.assertIn("对照样本 1", report)
        self.assertIn("高风险候选与对照样本之间的最低概率差距", report)
        self.assertIn("误报与局限性提示", report)

    def test_prompt_payload_contains_benign_controls_and_contrast_summary(self):
        high_event = make_event("high", 0.95, "high")
        control = select_benign_controls(
            [make_event("control", 0.08)],
            max_events=1,
            benign_threshold=0.5,
            source_label="benign.log",
        )
        messages = build_prompt([high_event], [], benign_controls=control, benign_note="note")
        content = messages[1]["content"]
        payload = json.loads(content[content.index("{") :])

        self.assertEqual(payload["benign_controls"][0]["uid"], "control")
        self.assertIn("良性对照与误报边界", payload["required_sections"])
        self.assertEqual(payload["risk_contrast_summary"], contrast_summary([high_event], control))


if __name__ == "__main__":
    unittest.main()
