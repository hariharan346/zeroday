import chromadb
from chromadb.utils import embedding_functions
from ingestor.parser import parse_directory
import os
import uuid

class VectorDBStore:
    def __init__(self, db_path="./chroma_db"):
        self.client = chromadb.PersistentClient(path=db_path)
        # Using the default ChromaDB embedding function (all-MiniLM-L6-v2)
        self.embedding_fn = embedding_functions.DefaultEmbeddingFunction()
        self.collection = self.client.get_or_create_collection(
            name="codebase_functions",
            embedding_function=self.embedding_fn
        )

    def ingest_codebase(self, directory: str):
        """
        Parses the given directory and stores the functions in ChromaDB.
        """
        print(f"📦 Ingesting codebase from {directory} into ChromaDB...")
        functions = parse_directory(directory)
        
        docs = []
        metadatas = []
        ids = []

        for func in functions:
            # We index the code itself
            docs.append(func["code"])
            
            # Convert lists to comma separated strings for ChromaDB metadata
            meta = {
                "file_path": func["file_path"],
                "function_name": func["function_name"],
                "calls": ",".join(func["calls"]),
                "repo": "local_microservices"
            }
            metadatas.append(meta)
            ids.append(str(uuid.uuid4()))

        if docs:
            self.collection.add(
                documents=docs,
                metadatas=metadatas,
                ids=ids
            )
            print(f"✅ Ingested {len(docs)} functions.")
        else:
            print("⚠️ No functions found to ingest.")

    def search_vulnerable_functions(self, keywords: list, limit: int = 5):
        """
        Search for functions matching CVE keywords.
        """
        query_text = " ".join(keywords)
        results = self.collection.query(
            query_texts=[query_text],
            n_results=limit
        )
        
        matches = []
        if results['documents'] and results['documents'][0]:
            for i in range(len(results['documents'][0])):
                matches.append({
                    "code": results['documents'][0][i],
                    "metadata": results['metadatas'][0][i],
                    "distance": results['distances'][0][i]
                })
        return matches

if __name__ == "__main__":
    store = VectorDBStore()
    store.ingest_codebase("services")
