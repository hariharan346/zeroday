import json
import os
import jedi
from typing import Dict, TypedDict, Any
from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate
from vector_db.chroma_store import VectorDBStore

# Define State
class AgentState(TypedDict):
    cve_data: Dict[str, Any]
    candidates: list
    vulnerable_function: Dict[str, Any]
    is_reachable: bool
    entry_point: str
    patch_diff: str

def triage_node(state: AgentState):
    """
    Step 1: Triage Node
    Queries ChromaDB for functions matching the CVE keywords.
    """
    print("🔍 [Triage Node] Querying vector DB for matching functions...")
    cve = state["cve_data"]
    db = VectorDBStore()
    
    # Query using CVE keywords
    results = db.search_vulnerable_functions(cve["keywords"], limit=3)
    
    candidates = []
    for res in results:
        meta = res["metadata"]
        # Basic filter to ensure the vulnerable function is actually in the code
        for vuln_func in cve["vulnerable_functions"]:
            if vuln_func in res["code"]:
                candidates.append({
                    "file_path": meta["file_path"],
                    "function_name": meta["function_name"],
                    "code": res["code"]
                })
    
    # For demo, take the first matching candidate
    vuln_func = candidates[0] if candidates else None
    if vuln_func:
        print(f"✅ [Triage Node] Vulnerable Function Found: {vuln_func['function_name']}")
        print(f"📍 [Triage Node] File: {vuln_func['file_path']}")
    else:
        print("✅ [Triage Node] No vulnerable functions found.")
        
    return {"candidates": candidates, "vulnerable_function": vuln_func}

def deep_scan_node(state: AgentState):
    """
    Step 2: Deep Scan Node
    Uses jedi to trace if the vulnerable function is reachable from an API entry point.
    """
    vuln_func = state.get("vulnerable_function")
    if not vuln_func:
        return {"is_reachable": False, "entry_point": None}

    print("🕵️  [Deep Scan Node] Using jedi to trace call graph...")
    target_func = vuln_func["function_name"]
    project_path = os.path.abspath("services")
    
    try:
        project = jedi.Project(project_path)
        # Search the project for references to the function name
        usages = project.search(target_func)
        
        reachable = False
        entry_point = None
        
        for usage in usages:
            # Check if it's used outside of its definition file
            if usage.module_path and os.path.abspath(usage.module_path) != os.path.abspath(vuln_func["file_path"]):
                # Read the file to see if it's a FastAPI/Flask route
                with open(usage.module_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    if "@app." in content or "@router." in content:
                        reachable = True
                        # Simple extraction for demo: get the route path
                        for line in content.split("\n"):
                            if line.strip().startswith("@app."):
                                entry_point = line.strip()
                                break
                        if not entry_point:
                            entry_point = os.path.basename(usage.module_path)
                        break
                        
        if reachable:
            print(f"⚠️  [Deep Scan Node] Reachable: YES")
            print(f"🌐 [Deep Scan Node] Entry Point: {entry_point}")
        else:
            print("🛡️  [Deep Scan Node] Not reachable from any known entry point.")
            
        return {"is_reachable": reachable, "entry_point": entry_point}
        
    except Exception as e:
        print(f"❌ [Deep Scan Node] Jedi error: {e}")
        return {"is_reachable": False, "entry_point": None}

def patch_generation_node(state: AgentState):
    """
    Step 3: Patch Generation Node
    Uses LLM to generate a safe patch in diff format.
    """
    if not state.get("is_reachable"):
        print("⏭️  [Patch Node] Skipping patch generation (not reachable).")
        return {"patch_diff": None}

    print("🛠️  [Patch Node] Generating patch (diff format)...")
    
    vuln_func = state["vulnerable_function"]
    cve = state["cve_data"]
    
    # Initialize LLM
    # NOTE: Requires OPENAI_API_KEY in environment
    try:
        llm = ChatOpenAI(temperature=0, model="gpt-3.5-turbo")
        
        prompt = PromptTemplate.from_template(
            "You are a DevSecOps Expert. A Zero-Day vulnerability has been found.\n"
            "CVE: {cve_id} - {cve_desc}\n\n"
            "Vulnerable Function Code:\n```python\n{code}\n```\n\n"
            "Generate a precise patch in standard git diff format that fixes the vulnerable logic. "
            "Do NOT rewrite the entire function unless necessary. Only fix the vulnerable part (e.g., replace pickle with json or add safe deserialization).\n"
            "Return ONLY the raw diff text, no markdown blocks."
        )
        
        chain = prompt | llm
        result = chain.invoke({
            "cve_id": cve["cve_id"],
            "cve_desc": cve["description"],
            "code": vuln_func["code"]
        })
        
        diff = result.content
        print("\n🛠 Patch Generated:")
        print("--------------------------------------------------")
        print(diff)
        print("--------------------------------------------------\n")
        
        return {"patch_diff": diff}
    except Exception as e:
        print(f"❌ [Patch Node] Error generating patch: {e}")
        # Provide a fallback patch for demo purposes if API key is missing
        fallback_diff = f"""--- a/{os.path.basename(vuln_func['file_path'])}
+++ b/{os.path.basename(vuln_func['file_path'])}
@@ -10,2 +10,3 @@
-        # VULNERABLE: pickle.loads can execute arbitrary code
-        return pickle.loads(decoded)
+        # SECURED: Replaced pickle with json
+        import json
+        return json.loads(decoded)
"""
        print("\n🛠 Fallback Patch (No LLM API Key):")
        print("--------------------------------------------------")
        print(fallback_diff)
        print("--------------------------------------------------\n")
        return {"patch_diff": fallback_diff}

def build_graph():
    workflow = StateGraph(AgentState)
    
    # Add nodes
    workflow.add_node("triage", triage_node)
    workflow.add_node("deep_scan", deep_scan_node)
    workflow.add_node("patch_gen", patch_generation_node)
    
    # Edges
    workflow.set_entry_point("triage")
    
    def condition_has_vuln(state: AgentState):
        if state.get("vulnerable_function"):
            return "deep_scan"
        return END

    workflow.add_conditional_edges("triage", condition_has_vuln)
    
    def condition_is_reachable(state: AgentState):
        if state.get("is_reachable"):
            return "patch_gen"
        return END

    workflow.add_conditional_edges("deep_scan", condition_is_reachable)
    workflow.add_edge("patch_gen", END)
    
    return workflow.compile()
