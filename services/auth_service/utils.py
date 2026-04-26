import pickle
import base64

def unsafe_load(data: str):
    """
    Vulnerable deserialization function.
    Reads base64 encoded pickle data.
    """
    try:
        decoded = base64.b64decode(data)
        # VULNERABLE: pickle.loads can execute arbitrary code
        return pickle.loads(decoded)
    except Exception as e:
        print(f"Error loading data: {e}")
        return None
