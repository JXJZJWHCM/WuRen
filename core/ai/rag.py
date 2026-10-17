import os
import math
import re
from collections import Counter
from typing import List, Dict, Any
from loguru import logger

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    SKLEARN_AVAILABLE = True
except Exception:
    TfidfVectorizer = None
    cosine_similarity = None
    SKLEARN_AVAILABLE = False

class DSARagEngine:
    def __init__(self, knowledge_path: str = "knowledge", skills_path: str = "skills"):
        """
        Initialize the DSA RAG Engine.
        Loads documents from the specified paths and builds the initial index.
        """
        self.knowledge_path = knowledge_path
        self.skills_path = skills_path
        self.documents: List[Dict[str, Any]] = []
        self.vectorizer = TfidfVectorizer(stop_words='english') if SKLEARN_AVAILABLE else None
        self.tfidf_matrix = None
        self.fallback_vectors: List[Counter] = []
        self.fallback_norms: List[float] = []
        
        self._load_documents()
        self._build_index()

    def _load_documents(self):
        """Load documents from knowledge and skills directories."""
        self._load_from_directory(self.knowledge_path, "knowledge")
        self._load_from_directory(self.skills_path, "skills")
        logger.info(f"Loaded {len(self.documents)} documents into RAG engine.")

    def _load_from_directory(self, path: str, doc_type: str):
        if not os.path.exists(path):
            logger.warning(f"Directory not found: {path}")
            return

        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith(('.txt', '.md', '.json', '.yaml', '.yml')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            if content.strip():  # Only add non-empty files
                                self.documents.append({
                                    "content": content,
                                    "source": file_path,
                                    "type": doc_type
                                })
                    except Exception as e:
                        logger.error(f"Failed to read file {file_path}: {e}")

    def _build_index(self):
        if not self.documents:
            logger.warning("No documents to index.")
            self.tfidf_matrix = None
            self.fallback_vectors = []
            self.fallback_norms = []
            return

        contents = [doc["content"] for doc in self.documents]
        if SKLEARN_AVAILABLE and self.vectorizer is not None:
            try:
                self.tfidf_matrix = self.vectorizer.fit_transform(contents)
                self.fallback_vectors = []
                self.fallback_norms = []
                logger.info("RAG index built successfully.")
                return
            except ValueError as e:
                logger.warning(f"Failed to build TF-IDF index: {e}")
                self.tfidf_matrix = None
        self._build_fallback_index(contents)
        logger.warning("RAG running in fallback mode without sklearn.")

    def add_document(self, content: str, source: str):
        """Add a new document to the index."""
        if not content.strip():
            return

        self.documents.append({
            "content": content,
            "source": source,
            "type": "dynamic"
        })
        self._build_index()

    def retrieve(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Retrieve relevant documents for the query.
        
        Args:
            query (str): The search query.
            top_k (int): Number of top results to return.
            
        Returns:
            List[Dict[str, Any]]: Top k relevant documents with scores.
        """
        if not self.documents:
            return []

        if SKLEARN_AVAILABLE and self.tfidf_matrix is not None and self.vectorizer is not None:
            try:
                query_vec = self.vectorizer.transform([query])
                cosine_similarities = cosine_similarity(query_vec, self.tfidf_matrix).flatten()
                related_docs_indices = cosine_similarities.argsort()[:-top_k-1:-1]
                results = []
                for idx in related_docs_indices:
                    score = cosine_similarities[idx]
                    if score > 0.01:
                        doc = self.documents[idx].copy()
                        doc["score"] = float(score)
                        results.append(doc)
                return results
            except Exception as e:
                logger.error(f"Error during retrieval: {e}")
                return []
        return self._retrieve_fallback(query, top_k)

    def _build_fallback_index(self, contents: List[str]) -> None:
        self.fallback_vectors = []
        self.fallback_norms = []
        for content in contents:
            vector = Counter(self._tokenize(content))
            norm = math.sqrt(sum(value * value for value in vector.values()))
            self.fallback_vectors.append(vector)
            self.fallback_norms.append(norm)

    def _retrieve_fallback(self, query: str, top_k: int) -> List[Dict[str, Any]]:
        query_vector = Counter(self._tokenize(query))
        query_norm = math.sqrt(sum(value * value for value in query_vector.values()))
        if query_norm <= 0:
            return []
        scored = []
        for idx, vector in enumerate(self.fallback_vectors):
            denominator = query_norm * (self.fallback_norms[idx] or 1.0)
            if denominator <= 0:
                score = 0.0
            else:
                dot = 0.0
                for token, value in query_vector.items():
                    dot += value * vector.get(token, 0.0)
                score = dot / denominator
            scored.append((idx, score))
        scored.sort(key=lambda item: item[1], reverse=True)
        results = []
        for idx, score in scored[:top_k]:
            if score > 0.01:
                doc = self.documents[idx].copy()
                doc["score"] = float(score)
                results.append(doc)
        return results

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        try:
            return [token for token in re.findall(r"[\w\u4e00-\u9fff]+", str(text).lower()) if token]
        except Exception as e:
            logger.error(f"Tokenize error: {e}")
            return []
