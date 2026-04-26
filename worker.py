import json
import time
import os
import glob
from agent.graph import build_graph

def get_latest_cve(cve_dir="cve"):
    """
    Simulates fetching the latest CVE from a feed.
    Here we just read all JSON files in the cve directory.
    """
    search_pattern = os.path.join(cve_dir, "*.json")
    files = glob.glob(search_pattern)
    cves = []
    for f in files:
        with open(f, "r", encoding="utf-8") as file:
            cves.append(json.load(file))
    return cves

def run_worker():
    print("🚀 Starting Zero-Day Exploit-to-Patch Automator Worker...")
    print("🔄 Polling for new CVEs every 30 seconds (simulated)...\n")
    
    graph = build_graph()
    processed_cves = set()
    
    # Run once immediately for the demo
    poll_count = 0
    max_polls = 2 # Limit for demo purposes so it doesn't run forever
    
    try:
        while poll_count < max_polls:
            cves = get_latest_cve()
            for cve in cves:
                cve_id = cve.get("cve_id")
                if cve_id not in processed_cves:
                    print(f"\n🚨 [Worker] NEW CVE DETECTED: {cve_id}")
                    print(f"📖 Description: {cve.get('description')}")
                    print("-" * 50)
                    
                    # Trigger the LangGraph pipeline
                    state = {"cve_data": cve}
                    final_state = graph.invoke(state)
                    
                    processed_cves.add(cve_id)
            
            print(f"💤 [Worker] Sleeping for 30 seconds... (Poll {poll_count+1}/{max_polls})")
            time.sleep(5) # Shortened to 5 seconds for faster demo execution
            poll_count += 1
            
        print("\n🏁 [Worker] Demo finished.")
            
    except KeyboardInterrupt:
        print("\n🛑 Worker stopped by user.")

if __name__ == "__main__":
    run_worker()
