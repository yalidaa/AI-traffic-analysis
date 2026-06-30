from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mineshark.evaluation.competition import evaluate_scenarios, load_scenarios, render_markdown, write_outputs


ROOT = Path(__file__).resolve().parents[1]


class CompetitionEvalTests(unittest.TestCase):
    def test_fixture_metrics_include_false_positive_and_false_negative(self):
        scenarios = load_scenarios(ROOT / "tests" / "fixtures" / "competition_scenarios")
        result = evaluate_scenarios(scenarios, threshold=0.70)

        self.assertEqual(result["scenario_count"], 10)
        self.assertEqual(result["label_counts"], {"benign": 5, "malware": 5})
        self.assertEqual(result["metrics"]["tp"], 4)
        self.assertEqual(result["metrics"]["fp"], 1)
        self.assertEqual(result["metrics"]["tn"], 4)
        self.assertEqual(result["metrics"]["fn"], 1)
        self.assertAlmostEqual(result["metrics"]["accuracy"], 0.8)
        self.assertEqual(result["false_positives"][0]["id"], "benign-ssh-002")
        self.assertEqual(result["false_negatives"][0]["id"], "attack-c2-002")

    def test_markdown_and_outputs_are_report_ready(self):
        scenarios = load_scenarios(ROOT / "tests" / "fixtures" / "competition_scenarios")
        result = evaluate_scenarios(scenarios, threshold=0.70)
        markdown = render_markdown(result)
        self.assertIn("面向加密通信协议的恶意行为检测技术", markdown)
        self.assertIn("Accuracy", markdown)
        self.assertIn("误报样例", markdown)

        with tempfile.TemporaryDirectory() as tmp:
            outputs = write_outputs(result, tmp)
            metrics = json.loads(Path(outputs["metrics"]).read_text(encoding="utf-8"))
            self.assertEqual(metrics["metrics"]["f1"], result["metrics"]["f1"])
            self.assertTrue(Path(outputs["comparison"]).exists())
            self.assertTrue(Path(outputs["table_data"]).exists())


if __name__ == "__main__":
    unittest.main()
