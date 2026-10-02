from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import os
from .config import settings
from .database import engine, SessionLocal, Base
# seed removed

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try: pass  # seed removed
    finally: db.close()
    yield

app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION, lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
from .routers import auth, employees, activities, screenshots, analytics, alerts, policies
for r in [auth, employees, activities, screenshots, analytics, alerts, policies]:
    app.include_router(r.router, prefix="/api/v1")
os.makedirs(settings.SCREENSHOT_STORAGE_PATH, exist_ok=True)
app.mount("/screenshots", StaticFiles(directory=settings.SCREENSHOT_STORAGE_PATH), name="screenshots")
@app.get("/health")
def health(): return {"status": "ok", "version": settings.APP_VERSION}
@app.get("/")
def root(): return {"message": "EmpMonitor API running", "docs": "/docs"}
