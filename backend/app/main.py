import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from .core.config import PROJECT_NAME, VERSION, STUDENT_NAME, STUDENT_ROLL, COURSE_NAME, UNIVERSITY
from .database.db import init_db
from .api.routes import api_router
from .mock_server import mock_router

# Locate frontend path
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

app = FastAPI(
    title=PROJECT_NAME,
    version=VERSION,
    description=f"{PROJECT_NAME} - Defensive Web Security & Posture Auditor by {STUDENT_NAME} ({STUDENT_ROLL}) for {COURSE_NAME}, {UNIVERSITY}"
)

# Enable CORS for API consumers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup database initialization
@app.on_event("startup")
def on_startup():
    init_db()

# Mount API and Mock routes
app.include_router(api_router)
app.include_router(mock_router)

# Mount frontend static directory if exists
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

@app.get("/")
def serve_index():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {
        "project": PROJECT_NAME,
        "author": f"{STUDENT_NAME} ({STUDENT_ROLL})",
        "course": COURSE_NAME,
        "status": "Online",
        "docs_url": "/docs"
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "system": PROJECT_NAME,
        "version": VERSION,
        "author": STUDENT_NAME,
        "roll_no": STUDENT_ROLL
    }
