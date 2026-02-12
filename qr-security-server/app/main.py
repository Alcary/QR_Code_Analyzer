import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.endpoints import scan
from app.core.config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: eagerly load ML models so first request isn't slow."""
    from app.services.ml.predictor import predictor  # noqa: F401

    logger.info("ML models loaded: %s", predictor.loaded)
    yield
    logger.info("Shutting down")


app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)

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
