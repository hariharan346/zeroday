import os
from vector_db.chroma_store import VectorDBStore
from worker import run_worker

def setup():
    print("=" * 50)
    print("Zero-Day Exploit-to-Patch Automator")
    print("=" * 50)
    
    # Ensure directories exist
    os.makedirs("services", exist_ok=True)
    os.makedirs("cve", exist_ok=True)
    
    # 1. Ingest Codebase
    store = VectorDBStore()
    store.ingest_codebase("services")
    
    # 2. Run Worker loop
    print("\nStarting Background Worker...")
    run_worker()

if __name__ == "__main__":
    # If using OpenAI, we should warn if no API key is set
    if not os.environ.get("OPENAI_API_KEY"):
        print("⚠️  WARNING: OPENAI_API_KEY not found in environment.")
        print("The agent will use the fallback patch generation logic.\n")
        
    setup()
