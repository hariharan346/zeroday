from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from services.auth_service.utils import unsafe_load

app = FastAPI()

class AuthRequest(BaseModel):
    token: str

@app.post("/login")
def login(req: AuthRequest):
    """
    Entry point for login that receives a base64 encoded token.
    """
    try:
        # Traceability: The unsafe_load is called here
        user_data = unsafe_load(req.token)
        if user_data:
            return {"status": "success", "user": user_data}
        else:
            raise HTTPException(status_code=400, detail="Invalid token")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
