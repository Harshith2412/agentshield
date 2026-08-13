"""Deterministic document retrieval with explicit trust labels."""

from dataclasses import dataclass

from agentshield.runtime.context import TrustBoundary


@dataclass(frozen=True)
class Document:
    name: str
    content: str
    boundary: TrustBoundary = TrustBoundary.LOCAL_TRUSTED


class DocumentStore:
    def __init__(self, documents: tuple[Document, ...] = ()) -> None:
        self._documents = {document.name: document for document in documents}

    def add(self, document: Document) -> None:
        self._documents[document.name] = document

    def retrieve(self, name: str) -> Document:
        try:
            return self._documents[name]
        except KeyError as exc:
            raise KeyError(f"document not found: {name}") from exc
