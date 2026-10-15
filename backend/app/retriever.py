import json
import os
from pathlib import Path
from typing import Any

import chromadb
from chromadb.api.types import EmbeddingFunction, Documents, Embeddings
from sentence_transformers import SentenceTransformer
from langchain_text_splitters import RecursiveCharacterTextSplitter

from .acl import chroma_acl_filter, relevant_denied_ids
from .contracts import Chunk, RetrievalResult, UserContext


class MiniLMEmbeddingFunction(EmbeddingFunction[Documents]):
    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        self.model = SentenceTransformer(model_name)

    def __call__(self, input: Documents) -> Embeddings:
        vectors = self.model.encode(
            list(input), normalize_embeddings=True, show_progress_bar=False
        )
        return vectors.tolist()


class AccessControlledRetriever:
    def __init__(self, persist_directory: str, documents_path: Path):
        Path(persist_directory).mkdir(parents=True, exist_ok=True)
        self.client = chromadb.PersistentClient(path=persist_directory)
        self.embedding_function = MiniLMEmbeddingFunction(
            os.getenv(
                "EMBEDDING_MODEL",
                "sentence-transformers/all-MiniLM-L6-v2",
            )
        )
        self.collection = self.client.get_or_create_collection(
            name="hinderman_documents",
            embedding_function=self.embedding_function,
            metadata={"hnsw:space": "cosine"},
        )
        self.documents_path = documents_path
        self.splitter = RecursiveCharacterTextSplitter(
            chunk_size=500,
            chunk_overlap=60,
            add_start_index=True,
        )
        self.ingest_seed_documents()

    def ingest_seed_documents(self) -> None:
        source = json.loads(self.documents_path.read_text(encoding="utf-8"))
        ids: list[str] = []
        texts: list[str] = []
        metadata: list[dict[str, Any]] = []

        for document in source:
            chunks = self.splitter.split_text(document["content"])
            for index, text in enumerate(chunks):
                ids.append(f'{document["doc_id"]}-{index:02d}')
                texts.append(text)
                row = {
                    "doc_id": document["doc_id"],
                    "title": document["title"],
                    "department": document["department"],
                    "classification": document["classification"],
                    "min_clearance": int(document["min_clearance"]),
                    "chunk_index": index,
                }
                row.update(
                    {
                        f"role_{role}": role in document["allowed_roles"]
                        for role in ("intern", "hr_officer", "finance_manager", "admin")
                    }
                )
                metadata.append(row)

        if ids:
            existing_ids = set(self.collection.get(ids=ids)["ids"])
            missing = [
                index for index, doc_id in enumerate(ids) if doc_id not in existing_ids
            ]
            if missing:
                self.collection.upsert(
                    ids=[ids[index] for index in missing],
                    documents=[texts[index] for index in missing],
                    metadatas=[metadata[index] for index in missing],
                )

    def retrieve(
        self, query: str, user: UserContext, k: int = 4
    ) -> RetrievalResult:
        count = self.collection.count()
        if count == 0:
            return RetrievalResult()

        candidate_limit = min(count, max(k * 4, 12))
        candidates = self.collection.query(
            query_texts=[query],
            n_results=candidate_limit,
            include=["metadatas", "distances"],
        )
        denied_ids = relevant_denied_ids(
            candidates["metadatas"][0],
            candidates["distances"][0],
            user.role,
            user.department,
            user.clearance,
        )

        permitted = self.collection.query(
            query_texts=[query],
            n_results=min(count, max(k * 4, k)),
            where=chroma_acl_filter(user.role, user.department, user.clearance),
            include=["documents", "metadatas", "distances"],
        )
        chunks: list[Chunk] = []
        seen_chunks: set[str] = set()
        for doc_id, text, item, distance in zip(
            permitted["ids"][0],
            permitted["documents"][0],
            permitted["metadatas"][0],
            permitted["distances"][0],
            strict=True,
        ):
            if doc_id in seen_chunks:
                continue
            seen_chunks.add(doc_id)
            chunks.append(
                Chunk(
                    doc_id=str(item["doc_id"]),
                    text=text,
                    score=max(-1.0, min(1.0, 1.0 - float(distance))),
                )
            )
            if len(chunks) == k:
                break

        return RetrievalResult(
            chunks=chunks,
            denied_count=len(denied_ids),
            denied_doc_ids=denied_ids,
        )

    def list_accessible_documents(self, user: UserContext) -> list[dict[str, Any]]:
        result = self.collection.get(
            where=chroma_acl_filter(user.role, user.department, user.clearance),
            include=["metadatas"],
        )
        unique: dict[str, dict[str, Any]] = {}
        for item in result["metadatas"]:
            doc_id = str(item["doc_id"])
            if doc_id not in unique:
                unique[doc_id] = {
                    "doc_id": doc_id,
                    "title": str(item["title"]),
                    "department": (
                        "All departments"
                        if item["department"] == "*"
                        else str(item["department"])
                    ),
                    "classification": str(item["classification"]),
                }
        return sorted(unique.values(), key=lambda document: document["title"])
