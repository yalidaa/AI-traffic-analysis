from __future__ import annotations

from typing import List, Sequence


class EmbeddingError(RuntimeError):
    pass


class QwenEmbeddingClient:
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
