import logging
from typing import List, Dict, Any
from langchain_core.documents import Document

logger = logging.getLogger("AgenticMemory")

class MockVectorStore:
    """
    A mock vector store to simulate Pinecone for long-term memory and context retention.
    In production, this would be backed by `langchain_pinecone.PineconeVectorStore`.
    """
    def __init__(self):
        self.memory_store: List[Document] = []
        logger.info("Initialized Mock Vector Store for agent memory.")

    def add_documents(self, documents: List[Document]) -> None:
        """Add new documents to the memory store."""
        for doc in documents:
            self.memory_store.append(doc)
            logger.info(f"Stored memory: {doc.page_content[:50]}...")

    def similarity_search(self, query: str, k: int = 4) -> List[Document]:
        """
        Simulate a similarity search. 
        For this mock, we just return the most recently added documents that might be relevant.
        """
        logger.info(f"Querying vector store for: {query}")
        # In a real scenario, this would compute embeddings and do cosine similarity.
        # Here we just return up to k recent documents as a mock.
        return list(reversed(self.memory_store))[:k]

# Global instance for the service
vector_store = MockVectorStore()
