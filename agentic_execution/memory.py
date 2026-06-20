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

class AuditLogger:
    """
    Maintains a robust, chronological audit trail of all agent decisions and HITL interventions 
    for explainability and regulatory compliance.
    """
    def __init__(self):
        self.trails: Dict[str, List[Dict[str, Any]]] = {}
        logger.info("Initialized Audit Logger.")

    def log_action(self, thread_id: str, actor: str, action: str, details: Dict[str, Any] = None):
        if thread_id not in self.trails:
            self.trails[thread_id] = []
        
        entry = {
            "actor": actor,
            "action": action,
            "details": details or {}
        }
        self.trails[thread_id].append(entry)
        logger.info(f"[AUDIT] {thread_id} | {actor} -> {action} | Details: {details}")

    def get_trail(self, thread_id: str) -> List[Dict[str, Any]]:
        return self.trails.get(thread_id, [])

# Global instances for the service
vector_store = MockVectorStore()
audit_logger = AuditLogger()

