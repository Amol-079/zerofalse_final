"""
Database — async-safe Supabase access via thread pool executor.

supabase-py is synchronous. Every call is offloaded to a bounded
ThreadPoolExecutor so the FastAPI async event loop is never blocked.
Pool size 20 handles 50-200 concurrent users comfortably.
"""
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from supabase import create_client, Client
from config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

_executor = ThreadPoolExecutor(max_workers=20, thread_name_prefix="supa")
_client: Client | None = None


def _get_client() -> Client:
    global _client
    if _client is None:
        _client = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_KEY)
        logger.info("Supabase client initialised")
    return _client


def get_supabase() -> Client:
    """Sync access — startup checks and webhook handlers only."""
    return _get_client()


class AsyncDB:
    """
    Wraps every Supabase call in run_in_executor.
    Usage: result = await db.execute(lambda c: c.table("x").select("*").execute())
    """
    def __init__(self):
        self._c = _get_client()

    async def execute(self, fn: Callable) -> Any:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_executor, fn, self._c)

    def sync(self) -> Client:
        return self._c


async def get_database() -> AsyncDB:
    """FastAPI dependency."""
    return AsyncDB()
