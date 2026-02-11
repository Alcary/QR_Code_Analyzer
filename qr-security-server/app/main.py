from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.endpoints import scan
from app.core.config import settings

app = FastAPI(title=settings.PROJECT_NAME)

# Set all CORS enabled origins
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.include_router(scan.router, prefix=settings.API_V1_STR)

@app.get("/")
def read_root():
    return {"status": "ok", "service": settings.PROJECT_NAME}
