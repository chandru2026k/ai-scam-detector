from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import scan, feedback

app = FastAPI(title="AI Scam Detector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router, prefix="/api/scan", tags=["scan"])
app.include_router(feedback.router, prefix="/api/feedback", tags=["feedback"])

@app.get("/")
def root():
    return {"status": "AI Scam Detector API is running"}