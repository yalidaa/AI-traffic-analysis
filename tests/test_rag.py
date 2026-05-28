import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mineshark.rag.store import FaissKnowledgeStore, build_faiss_index, load_knowledge_jsonl


class FakeEmbeddingClient:
    def embed_texts(self, texts):
        vectors = []
        for text in texts:
            vectors.append([float("c2" in text.lower()), float("wazuh" in text.lower()), 1.0])
        return vectors


class RagTests(unittest.TestCase):
    @unittest.skipIf(importlib.util.find_spec("faiss") is None, "faiss-cpu is not installed")
    def test_build_and_search_faiss_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            knowledge = root / "kb.jsonl"
            knowledge.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "title": "C2 communication",
                                "tags": ["c2"],
                                "content": "beacon",
                                "recommendation": "check domain",
                                "severity_hint": "high",
                                "evidence_required": ["zeek_uid", "wazuh_rule"],
                                "false_positive_notes": "cdn can look similar",
                                "recommended_queries": ["query_zeek_context"],
                            }
                        ),
                        json.dumps(
                            {
                                "title": "Wazuh alert",
                                "tags": ["wazuh"],
                                "content": "alert",
                                "recommendation": "check agent",
                            }
                        ),
                    ]
                ),
                encoding="utf-8",
            )
            records = load_knowledge_jsonl(knowledge)
            self.assertEqual(records[0].severity_hint, "high")
            self.assertIn("zeek_uid", records[0].text)
            self.assertIn("cdn can look similar", records[0].text)
            build_faiss_index(records, FakeEmbeddingClient(), root / "rag")
            store = FaissKnowledgeStore(root / "rag", FakeEmbeddingClient())
            matches = store.search("wazuh alert", top_k=1)
            self.assertEqual(matches[0]["title"], "Wazuh alert")


if __name__ == "__main__":
    unittest.main()
