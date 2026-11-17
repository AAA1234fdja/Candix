"""Local vector representations for retrieval without a model call.

Two complementary signals: hashed token vectors (fast, robust to typos) and
character n-gram vectors (good for identifiers like ``/api/v1/users?id=``).
Everything is local, deterministic and dependency free, which is what makes the
skill and lesson retrieval work offline.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Sequence

_TOKEN = re.compile(r"[A-Za-z0-9_./?=&-]+")
_STOP = frozenset(
    "a an and are as at be by for from has have in is it its of on or that the this to was were will with".split()
)


def tokenize(text: str, *, min_length: int = 2) -> list[str]:
    tokens = []
    for raw in _TOKEN.findall(str(text or "").lower()):
        if len(raw) < min_length:
            continue
        if raw in _STOP:
            continue
        tokens.append(raw)
        if any(separator in raw for separator in "/?=&"):
            tokens.extend(part for part in re.split(r"[/?=&]", raw) if len(part) >= min_length)
    return tokens


def ngrams(text: str, size: int = 3) -> list[str]:
    compact = re.sub(r"\s+", " ", str(text or "").lower())
    return [compact[index : index + size] for index in range(max(0, len(compact) - size + 1))]


def _bucket(term: str, dimensions: int) -> int:
    digest = hashlib.blake2b(term.encode("utf-8"), digest_size=4).digest()
    return int.from_bytes(digest, "big") % dimensions


def hash_vector(text: str, *, dimensions: int = 256, bigrams: bool = True) -> dict[int, float]:
    counts: Counter[str] = Counter(tokenize(text))
    if bigrams:
        tokens = tokenize(text)
        counts.update(f"{first}_{second}" for first, second in zip(tokens, tokens[1:]))
    vector: dict[int, float] = {}
    for term, count in counts.items():
        index = _bucket(term, dimensions)
        vector[index] = vector.get(index, 0.0) + (1.0 + math.log(count))
    return vector


def char_vector(text: str, *, dimensions: int = 256, size: int = 3) -> dict[int, float]:
    vector: dict[int, float] = {}
    for gram in ngrams(text, size):
        index = _bucket(gram, dimensions)
        vector[index] = vector.get(index, 0.0) + 1.0
    return vector


def normalise(vector: dict[int, float]) -> dict[int, float]:
    length = math.sqrt(sum(value * value for value in vector.values()))
    if not length:
        return {}
    return {index: value / length for index, value in vector.items()}


def cosine(first: dict[int, float], second: dict[int, float]) -> float:
    if not first or not second:
        return 0.0
    if len(first) > len(second):
        first, second = second, first
    return sum(value * second.get(index, 0.0) for index, value in first.items())


@dataclass
class Document:
    id: str
    text: str
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass
class Scored:
    document: Document
    score: float
    lexical: float = 0.0
    semantic: float = 0.0


class VectorIndex:
    """Hybrid lexical + hashed-vector index for small corpora."""

    def __init__(self, *, dimensions: int = 256, semantic_weight: float = 0.55) -> None:
        self.dimensions = dimensions
        self.semantic_weight = semantic_weight
        self.documents: list[Document] = []
        self._vectors: dict[str, dict[int, float]] = {}

    def add(self, document: Document) -> None:
        self.documents.append(document)
        combined = hash_vector(document.text, dimensions=self.dimensions)
        characters = char_vector(document.text, dimensions=self.dimensions)
        merged = {index: value for index, value in combined.items()}
        for index, value in characters.items():
            merged[index] = merged.get(index, 0.0) + value * 0.5
        self._vectors[document.id] = normalise(merged)

    def extend(self, documents: Iterable[Document]) -> None:
        for document in documents:
            self.add(document)

    def search(self, query: str, *, limit: int = 5) -> list[Scored]:
        if not self.documents:
            return []
        query_vector = normalise(hash_vector(query, dimensions=self.dimensions))
        query_tokens = set(tokenize(query))
        results: list[Scored] = []
        for document in self.documents:
            semantic = cosine(query_vector, self._vectors.get(document.id, {}))
            document_tokens = set(tokenize(document.text))
            lexical = len(query_tokens & document_tokens) / len(query_tokens) if query_tokens else 0.0
            score = self.semantic_weight * semantic + (1 - self.semantic_weight) * lexical
            if score > 0:
                results.append(Scored(document, round(score, 4), round(lexical, 4), round(semantic, 4)))
        results.sort(key=lambda item: (-item.score, item.document.id))
        return results[:limit]

    def __len__(self) -> int:
        return len(self.documents)


def best_match(query: str, candidates: Sequence[str]) -> tuple[int, float]:
    index = VectorIndex()
    for position, candidate in enumerate(candidates):
        index.add(Document(str(position), candidate))
    hits = index.search(query, limit=1)
    if not hits:
        return -1, 0.0
    return int(hits[0].document.id), hits[0].score


def cluster(texts: Sequence[str], *, threshold: float = 0.62) -> list[list[int]]:
    """Group near-duplicate strings, e.g. findings that are one issue."""

    vectors = [normalise(hash_vector(text)) for text in texts]
    groups: list[list[int]] = []
    assigned: set[int] = set()
    for index, vector in enumerate(vectors):
        if index in assigned:
            continue
        group = [index]
        assigned.add(index)
        for other in range(index + 1, len(vectors)):
            if other in assigned:
                continue
            if cosine(vector, vectors[other]) >= threshold:
                group.append(other)
                assigned.add(other)
        groups.append(group)
    return groups
