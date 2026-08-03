from __future__ import annotations

import hashlib
import re
from typing import List, Sequence


class EmbeddingError(RuntimeError):
    pass


class QwenEmbeddingClient:
    provider = "dashscope-qwen"

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://dashscope.aliyuncs.com/compatible-mode/v1",
        model: str = "text-embedding-v4",
        timeout: int = 60,
    ):
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.timeout = timeout

    def embed_texts(self, texts: Sequence[str]) -> List[List[float]]:
        if not self.api_key:
            raise EmbeddingError("DASHSCOPE_API_KEY is required for Qwen embeddings.")
        try:
            from openai import OpenAI
        except Exception as exc:
            raise EmbeddingError("openai package is required for Qwen embeddings.") from exc

        client = OpenAI(api_key=self.api_key, base_url=self.base_url, timeout=self.timeout)
        response = client.embeddings.create(model=self.model, input=list(texts))
        return [list(item.embedding) for item in response.data]


class LocalEmbeddingClient:
    """Deterministic offline embedding for local playbook retrieval."""

    provider = "local-hash"

    def __init__(self, dimension: int = 384):
        self.dimension = dimension

    def embed_texts(self, texts: Sequence[str]) -> List[List[float]]:
        vectors: List[List[float]] = []
        for text in texts:
            vector = [0.0] * self.dimension
            tokens = re.findall(r"[a-z0-9_:.@/-]+|[\u4e00-\u9fff]", str(text).lower())
            for token in tokens:
                digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
                index = int.from_bytes(digest[:4], "little") % self.dimension
                sign = 1.0 if digest[4] & 1 else -1.0
                vector[index] += sign
            vectors.append(vector)
        return vectors
