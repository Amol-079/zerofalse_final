import sys
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from config import get_settings
from database import get_supabase
import cache as _cache

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Zerofalse API [%s]", settings.ENVIRONMENT)
    try:
        get_supabase().table("organizations").select("id").limit(1).execute()
        logger.info("Supabase OK")
    except Exception as e:
        logger.critical("Supabase failed: %s", e)
        sys.exit(1)
    await _cache.get_redis()
    logger.info("Ready")
    yield
    await _cache.close()


app = FastAPI(
    title="Zerofalse API",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://zerofalse-final.vercel.app",
        "http://localhost:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def limit_body(request: Request, call_next) -> Response:
    cl = request.headers.get("content-length")
    if cl and int(cl) > settings.MAX_REQUEST_BODY_BYTES:
        return Response("Request body too large", status_code=413)
    return await call_next(request)


@app.get("/health", include_in_schema=False)
async def health():
    return {"status": "healthy", "version": "2.0.0"}


@app.get("/", include_in_schema=False)
async def root():
    return {"status": "healthy", "version": "2.0.0"}


from routers.auth import router as auth_router
from routers.clerk_webhook import router as clerk_webhook_router
from routers.scan import router as scan_router
from routers.dashboard import router as dashboard_router
from routers.api_keys import router as keys_router
from routers.alerts import router as alerts_router
from routers.webhooks import router as webhooks_router

app.include_router(auth_router,          prefix="/api/v1")
app.include_router(clerk_webhook_router, prefix="/api/v1")
app.include_router(scan_router,          prefix="/api/v1")
app.include_router(dashboard_router,     prefix="/api/v1")
app.include_router(keys_router,          prefix="/api/v1")
app.include_router(alerts_router,        prefix="/api/v1")
app.include_router(webhooks_router,      prefix="/api/v1")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
