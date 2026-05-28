from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Sequence

import numpy as np


INDEX_FILE = "knowledge.faiss"
METADATA_FILE = "metadata.json"


@dataclass(frozen=True)
class KnowledgeRecord:
    title: str
    tags: List[str]
    content: str
    recommendation: str
    severity_hint: str
    evidence_required: List[str]
    false_positive_notes: str
    recommended_queries: List[str]
    raw: Dict[str, Any]

    @property
    def text(self) -> str:
        return " ".join(
            [
                self.title,
                " ".join(self.tags),
                self.content,
                self.recommendation,
                self.severity_hint,
                " ".join(self.evidence_required),
                self.false_positive_notes,
                " ".join(self.recommended_queries),
            ]
        ).strip()

    def to_metadata(self) -> Dict[str, Any]:
        payload = dict(self.raw)
        payload.setdefault("title", self.title)
        payload.setdefault("tags", self.tags)
        payload.setdefault("content", self.content)
        payload.setdefault("recommendation", self.recommendation)
        payload.setdefault("severity_hint", self.severity_hint)
        payload.setdefault("evidence_required", self.evidence_required)
        payload.setdefault("false_positive_notes", self.false_positive_notes)
        payload.setdefault("recommended_queries", self.recommended_queries)
        return payload


def load_knowledge_jsonl(path: Path) -> List[KnowledgeRecord]:
    records: List[KnowledgeRecord] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            records.append(
                KnowledgeRecord(
                    title=str(raw.get("title", "")),
                    tags=list(raw.get("tags", [])),
                    content=str(raw.get("content", "")),
                    recommendation=str(raw.get("recommendation", "")),
                    severity_hint=str(raw.get("severity_hint", "")),
                    evidence_required=list(raw.get("evidence_required", [])),
                    false_positive_notes=str(raw.get("false_positive_notes", "")),
                    recommended_queries=list(raw.get("recommended_queries", [])),
                    raw=raw,
                )
            )
    return records


def _normalise(vectors: Sequence[Sequence[float]]) -> np.ndarray:
    arr = np.asarray(vectors, dtype=np.float32)
    if arr.ndim != 2 or arr.shape[0] == 0:
        raise ValueError("Embeddings must be a non-empty 2D array.")
    norms = np.linalg.norm(arr, axis=1, keepdims=True)
    norms = np.maximum(norms, 1e-12)
    return arr / norms


def build_faiss_index(records: List[KnowledgeRecord], embedding_client, output_dir: Path) -> Dict[str, Any]:
    if not records:
        raise ValueError("No knowledge records were loaded.")
    try:
        import faiss
    except Exception as exc:
        raise RuntimeError("faiss-cpu is required to build the RAG index.") from exc

    texts = [record.text for record in records]
    embeddings = _normalise(embedding_client.embed_texts(texts))
    index = faiss.IndexFlatIP(embeddings.shape[1])
    index.add(embeddings)

    output_dir.mkdir(parents=True, exist_ok=True)
    faiss.write_index(index, str(output_dir / INDEX_FILE))
    metadata = {
        "dimension": int(embeddings.shape[1]),
        "count": len(records),
        "records": [record.to_metadata() for record in records],
    }
    (output_dir / METADATA_FILE).write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return {"index_file": str(output_dir / INDEX_FILE), "metadata_file": str(output_dir / METADATA_FILE), **metadata}


class FaissKnowledgeStore:
    def __init__(self, index_dir: Path, embedding_client):
        self.index_dir = index_dir
        self.embedding_client = embedding_client
        self._index = None
        self._records: List[Dict[str, Any]] = []

    def load(self) -> None:
        try:
            import faiss
        except Exception as exc:
            raise RuntimeError("faiss-cpu is required to load the RAG index.") from exc

        index_path = self.index_dir / INDEX_FILE
        metadata_path = self.index_dir / METADATA_FILE
        if not index_path.exists() or not metadata_path.exists():
            raise FileNotFoundError(
                f"RAG index is missing. Run mineshark-build-rag first: {self.index_dir}"
            )
        self._index = faiss.read_index(str(index_path))
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        self._records = list(metadata.get("records", []))

    def search(self, query: str, top_k: int = 4) -> List[Dict[str, Any]]:
        if self._index is None:
            self.load()
        if not query.strip():
            return []
        query_vec = _normalise(self.embedding_client.embed_texts([query]))
        scores, indices = self._index.search(query_vec, top_k)
        matches: List[Dict[str, Any]] = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < 0 or idx >= len(self._records):
                continue
            item = dict(self._records[int(idx)])
            item["score"] = float(score)
            matches.append(item)
        return matches
