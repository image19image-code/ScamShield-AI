from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from security_engine import analyze_message


app = FastAPI(
    title="ScamShield AI API",
    description="Defensive phishing and scam analysis API",
    version="1.0.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    text: str


@app.get("/")
def root():
    return {
        "name": "ScamShield AI",
        "status": "online",
        "message": "Security analysis API is running"
    }


@app.post("/analyze")
def analyze(request: AnalyzeRequest):
    if not request.text.strip():
        return {
            "error": "Please provide a message or URL to analyze."
        }

    return analyze_message(request.text)
