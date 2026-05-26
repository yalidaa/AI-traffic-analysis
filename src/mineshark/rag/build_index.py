from __future__ import annotations

import argparse

from mineshark.config import RuntimeConfig, resolve_project_path
from mineshark.rag.embeddings import QwenEmbeddingClient
from mineshark.rag.store import build_faiss_index, load_knowledge_jsonl


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build MineShark FAISS RAG index.")
    parser.add_argument("--env-file", default=None)
    parser.add_argument("--knowledge-file", default=None)
    parser.add_argument("--output-dir", default=None)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    config = RuntimeConfig.from_env(args.env_file)
    knowledge_file = resolve_project_path(args.knowledge_file) if args.knowledge_file else config.knowledge_file
    output_dir = resolve_project_path(args.output_dir) if args.output_dir else config.rag_index_dir

    records = load_knowledge_jsonl(knowledge_file)
    embedding_client = QwenEmbeddingClient(
        api_key=config.dashscope_api_key,
        base_url=config.dashscope_base_url,
        model=config.dashscope_embedding_model,
    )
    result = build_faiss_index(records, embedding_client, output_dir)
    print(f"Knowledge records: {result['count']}")
    print(f"FAISS index: {result['index_file']}")
    print(f"Metadata: {result['metadata_file']}")


if __name__ == "__main__":
    main()
