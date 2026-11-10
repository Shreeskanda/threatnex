import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.database import Base, engine, create_tables
from app.config import settings
from app.api.scan import router as scan_router
from app.api.history import router as history_router
from app.api.awareness import router as awareness_router
from app.api.quiz import router as quiz_router
from app.api.dashboard import router as dashboard_router
from app.api.reports import router as reports_router

# Ensure tables exist immediately on startup
create_tables()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure tables are created and uploads directory exists
    Base.metadata.create_all(bind=engine)
    uploads_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "uploads")
    os.makedirs(uploads_dir, exist_ok=True)
    yield
    # Shutdown logic if needed


app = FastAPI(
    title="THREATNEX API",
    description="Enterprise Multimodal Cyber Threat Intelligence & Digital Safety Engine",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*"
    ],
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Exception Handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": f"Internal Server Error: {str(exc)}"}
    )

# Include all API routers under the /api namespace
app.include_router(scan_router, prefix="/api")
app.include_router(history_router, prefix="/api")
app.include_router(awareness_router, prefix="/api")
app.include_router(quiz_router, prefix="/api")
app.include_router(dashboard_router, prefix="/api")
app.include_router(reports_router, prefix="/api")


@app.get("/")
async def root():
    return {
        "platform": "THREATNEX",
        "status": "operational",
        "documentation": "/docs"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
